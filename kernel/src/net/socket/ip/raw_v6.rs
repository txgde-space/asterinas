// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    options::{Ipv6OptionSet, SetIpV6LevelOption},
    raw::check_raw_socket_privilege,
};
use crate::{
    events::IoEvents,
    fs::{pseudofs::SockFs, vfs::path::Path},
    net::socket::{
        Socket,
        options::SocketOption,
        private::SocketPrivate,
        util::{
            ControlMessage, IpExtendedError, Ipv6Address, Ipv6ControlMessage, MessageHeader,
            SendRecvFlags, SocketAddr,
        },
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    util::{MultiRead, MultiWrite},
};

const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_RAW: u8 = 255;
const IPV6_HEADER_LEN: usize = 40;
const RAW_RECV_PACKET_LIMIT: usize = 64;
const RAW_RECV_BYTE_LIMIT: usize = 256 * 1024;
const MAX_ERROR_QUEUE: usize = 16;

/// A raw IPv6 socket backed by the kernel loopback path.
///
/// This stage intentionally keeps the Ethernet/router path unchanged. It
/// nevertheless implements the complete AF_INET6 raw socket ABI needed by
/// `ping -6 ::1`, protocol probes, `IPV6_HDRINCL`, ancillary hop-limit and
/// traffic-class control, and the local error queue. The next IPv6 stage wires
/// the same packet representation into Ethernet and route lookup.
pub struct Ipv6RawSocket {
    /// `None` represents Linux's IPPROTO_RAW send-any-protocol socket.
    protocol: Option<u8>,
    recv_queue: RwLock<RawIpv6RecvQueue>,
    local_endpoint: RwLock<Option<Ipv6Endpoint>>,
    remote_endpoint: RwLock<Option<Ipv6Endpoint>>,
    is_nonblocking: AtomicBool,
    options: RwLock<Ipv6OptionSet>,
    error_queue: RwLock<VecDeque<RawIpv6Error>>,
    pollee: Pollee,
    pseudo_path: Path,
}

impl Ipv6RawSocket {
    /// Creates an IPv6 raw socket after checking `CAP_NET_RAW`.
    pub fn new(is_nonblocking: bool, protocol: i32) -> Result<Arc<Self>> {
        check_raw_socket_privilege()?;
        let protocol = raw_ipv6_protocol(protocol)?;

        Ok(Arc::new(Self {
            protocol,
            recv_queue: RwLock::new(RawIpv6RecvQueue::new()),
            local_endpoint: RwLock::new(None),
            remote_endpoint: RwLock::new(None),
            is_nonblocking: AtomicBool::new(is_nonblocking),
            options: RwLock::new(Ipv6OptionSet::new_raw()),
            error_queue: RwLock::new(VecDeque::new()),
            pollee: Pollee::new(),
            pseudo_path: SockFs::new_path(),
        }))
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        if flags.contains(SendRecvFlags::MSG_ERRQUEUE) {
            let error = self
                .error_queue
                .write()
                .pop_front()
                .ok_or_else(|| Error::with_message(Errno::EAGAIN, "the IPv6 error queue is empty"))?;
            self.pollee.invalidate();
            return Ok((
                0,
                MessageHeader::new(
                    Some(SocketAddr::IPv6(error.destination, 0, 0, 0)),
                    vec![ControlMessage::IpV6(Ipv6ControlMessage::ExtendedError(
                        error.extended,
                    ))],
                ),
            ));
        }

        if self.protocol.is_none() {
            return_errno_with_message!(
                Errno::EOPNOTSUPP,
                "IPPROTO_RAW sockets are send-only"
            );
        }

        let packet = self
            .recv_queue
            .write()
            .pop()
            .ok_or_else(|| Error::with_message(Errno::EAGAIN, "the IPv6 receive queue is empty"))?;
        let received_bytes = writer.write(&mut VmReader::from(packet.bytes.as_slice()))?;
        let options = *self.options.read();
        let mut controls = Vec::new();
        if options.recv_hoplimit() {
            controls.push(ControlMessage::IpV6(Ipv6ControlMessage::HopLimit(
                packet.hop_limit as i32,
            )));
        }
        if options.recv_tclass() {
            controls.push(ControlMessage::IpV6(Ipv6ControlMessage::TClass(
                packet.traffic_class as i32,
            )));
        }
        self.pollee.invalidate();

        Ok((
            received_bytes,
            MessageHeader::new(
                Some(SocketAddr::IPv6(packet.source, 0, 0, 0)),
                controls,
            ),
        ))
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        if !flags.is_all_supported() {
            warn!("unsupported IPv6 raw socket flags: {:?}", flags);
        }

        let MessageHeader {
            addr,
            control_messages,
        } = message_header;
        let (control_hop_limit, control_tclass) = raw_ipv6_control_options(&control_messages)?;
        let destination = match addr {
            Some(SocketAddr::IPv6(destination, _, _, _)) => destination,
            Some(_) => {
                return_errno_with_message!(
                    Errno::EAFNOSUPPORT,
                    "raw IPv6 sockets require an IPv6 destination address"
                )
            }
            None => self
                .remote_endpoint
                .read()
                .ok_or_else(|| {
                    Error::with_message(
                        Errno::EDESTADDRREQ,
                        "raw IPv6 sockets require an IPv6 destination address",
                    )
                })?
                .addr,
        };

        let mut packet = vec![0; reader.sum_lens()];
        let sent_bytes = reader.read(&mut VmWriter::from(packet.as_mut_slice()))?;
        packet.truncate(sent_bytes);

        let options = *self.options.read();
        let parsed_header = if options.hdrincl() {
            Some(parse_hdrincl_ipv6_packet(&packet)?)
        } else {
            None
        };

        if self.protocol.is_none() && parsed_header.is_none() {
            return_errno_with_message!(
                Errno::EINVAL,
                "IPPROTO_RAW requires IPV6_HDRINCL to select a protocol"
            );
        }

        let destination = parsed_header
            .as_ref()
            .map_or(destination, |header| header.destination);
        let next_header = parsed_header.as_ref().map_or_else(
            || {
                self.protocol.ok_or_else(|| {
                    Error::with_message(
                        Errno::EINVAL,
                        "IPPROTO_RAW requires IPV6_HDRINCL to select a protocol",
                    )
                })
            },
            |header| Ok(header.next_header),
        )?;
        if self.protocol.is_some_and(|protocol| protocol != next_header) {
            return_errno_with_message!(
                Errno::EINVAL,
                "IPV6_HDRINCL next-header does not match the raw socket"
            );
        }

        if destination.is_unspecified() {
            self.queue_local_error(destination, Errno::ENETUNREACH);
            return_errno_with_message!(Errno::ENETUNREACH, "the IPv6 destination is unspecified");
        }
        if !destination.is_loopback() {
            self.queue_local_error(destination, Errno::ENETUNREACH);
            return_errno_with_message!(
                Errno::ENETUNREACH,
                "the IPv6 route is not available in this stage"
            );
        }

        let local_endpoint = self.local_endpoint.read().unwrap_or(Ipv6Endpoint {
            addr: Ipv6Address::LOOPBACK,
            flowinfo: 0,
            scope_id: 0,
        });
        let local = if local_endpoint.addr.is_unspecified() {
            Ipv6Address::LOOPBACK
        } else {
            local_endpoint.addr
        };
        let source = parsed_header.as_ref().map_or(local, |header| {
            if header.source.is_unspecified() {
                local
            } else {
                header.source
            }
        });
        let traffic_class = parsed_header.as_ref().map_or(
            control_tclass.unwrap_or(options.tclass()),
            |header| header.traffic_class,
        );
        let hop_limit = parsed_header.as_ref().map_or(
            control_hop_limit.unwrap_or(options.hop_limit().get()),
            |header| header.hop_limit,
        );
        let payload = parsed_header
            .as_ref()
            .map_or(packet.as_slice(), |header| &packet[IPV6_HEADER_LEN..header.total_len]);
        if parsed_header.is_none() && payload.len() > u16::MAX as usize {
            return_errno_with_message!(
                Errno::EMSGSIZE,
                "an IPv6 raw payload must fit in the 16-bit payload-length field"
            );
        }

        if next_header == IPPROTO_ICMPV6 && is_icmpv6_echo_request(payload) {
            let mut reply_payload = payload.to_vec();
            reply_payload[0] = 129;
            reply_payload[2] = 0;
            reply_payload[3] = 0;
            let reply = build_ipv6_packet(
                destination,
                source,
                next_header,
                traffic_class,
                hop_limit,
                &mut reply_payload,
            );
            self.enqueue_received(RawIpv6Packet {
                bytes: reply,
                source: destination,
                traffic_class,
                hop_limit,
            });
        } else {
            let bytes = if parsed_header.is_some() {
                packet
            } else {
                build_ipv6_packet(
                    source,
                    destination,
                    next_header,
                    traffic_class,
                    hop_limit,
                    &mut packet,
                )
            };
            self.enqueue_received(RawIpv6Packet {
                bytes,
                source,
                traffic_class,
                hop_limit,
            });
        }

        self.pollee.notify(IoEvents::IN);
        Ok(sent_bytes)
    }

    fn enqueue_received(&self, packet: RawIpv6Packet) {
        let mut queue = self.recv_queue.write();
        let _ = queue.push(packet);
    }

    fn queue_local_error(&self, destination: Ipv6Address, errno: Errno) {
        if !self.options.read().recverr() {
            return;
        }

        const SO_EE_ORIGIN_LOCAL: u8 = 1;
        let mut queue = self.error_queue.write();
        if queue.len() >= MAX_ERROR_QUEUE {
            queue.pop_front();
        }
        queue.push_back(RawIpv6Error {
            destination,
            extended: IpExtendedError {
                errno: errno as u32,
                origin: SO_EE_ORIGIN_LOCAL,
                type_: 0,
                code: 0,
                pad: 0,
                info: 0,
                data: 0,
            },
        });
        drop(queue);
        self.pollee.notify(IoEvents::ERR);
    }

    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::OUT;
        if self.protocol.is_some() && !self.recv_queue.read().is_empty() {
            events |= IoEvents::IN;
        }
        if !self.error_queue.read().is_empty() {
            events |= IoEvents::ERR;
        }
        events
    }
}

impl Pollable for Ipv6RawSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }
}

impl SocketPrivate for Ipv6RawSocket {
    fn is_nonblocking(&self) -> bool {
        self.is_nonblocking.load(Ordering::Relaxed)
    }

    fn set_nonblocking(&self, is_nonblocking: bool) {
        self.is_nonblocking.store(is_nonblocking, Ordering::Relaxed);
    }
}

impl Socket for Ipv6RawSocket {
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let SocketAddr::IPv6(addr, _, flowinfo, scope_id) = socket_addr else {
            return_errno_with_message!(Errno::EAFNOSUPPORT, "IPv6 raw sockets require AF_INET6");
        };
        if !addr.is_unspecified() && !addr.is_loopback() {
            return_errno_with_message!(
                Errno::EADDRNOTAVAIL,
                "only the IPv6 loopback address is available in this stage"
            );
        }
        *self.local_endpoint.write() = Some(Ipv6Endpoint {
            addr,
            flowinfo,
            scope_id,
        });
        Ok(())
    }

    fn connect(&self, socket_addr: SocketAddr) -> Result<()> {
        let SocketAddr::IPv6(addr, _, flowinfo, scope_id) = socket_addr else {
            return_errno_with_message!(Errno::EAFNOSUPPORT, "IPv6 raw sockets require AF_INET6");
        };
        *self.remote_endpoint.write() = Some(Ipv6Endpoint {
            addr,
            flowinfo,
            scope_id,
        });
        Ok(())
    }

    fn addr(&self) -> Result<SocketAddr> {
        let endpoint = self
            .local_endpoint
            .read()
            .unwrap_or(Ipv6Endpoint {
                addr: Ipv6Address::UNSPECIFIED,
                flowinfo: 0,
                scope_id: 0,
            });
        Ok(SocketAddr::IPv6(
            endpoint.addr,
            0,
            endpoint.flowinfo,
            endpoint.scope_id,
        ))
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let endpoint = self.remote_endpoint.read().ok_or_else(|| {
            Error::with_message(Errno::ENOTCONN, "the IPv6 raw socket is not connected")
        })?;
        Ok(SocketAddr::IPv6(
            endpoint.addr,
            0,
            endpoint.flowinfo,
            endpoint.scope_id,
        ))
    }

    fn sendmsg(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        self.try_send(reader, message_header, flags)
    }

    fn recvmsg(
        &self,
        writer: &mut dyn MultiWrite,
        flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        let events = if flags.contains(SendRecvFlags::MSG_ERRQUEUE) {
            IoEvents::ERR
        } else {
            IoEvents::IN
        };
        self.block_on(events, || self.try_recv(writer, flags))
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        self.options.read().get_option(option)
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        self.options
            .write()
            .set_option(option, self)
            .map(|_| ())
    }

    fn pseudo_path(&self) -> &Path {
        &self.pseudo_path
    }
}

impl SetIpV6LevelOption for Ipv6RawSocket {
    fn set_hdrincl(&self, _hdrincl: bool) -> Result<()> {
        Ok(())
    }
}

impl fmt::Debug for Ipv6RawSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ipv6RawSocket")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
struct Ipv6Endpoint {
    addr: Ipv6Address,
    flowinfo: u32,
    scope_id: u32,
}

#[derive(Debug)]
struct RawIpv6Packet {
    bytes: Vec<u8>,
    source: Ipv6Address,
    traffic_class: u8,
    hop_limit: u8,
}

struct RawIpv6RecvQueue {
    packets: VecDeque<RawIpv6Packet>,
    queued_bytes: usize,
}

impl RawIpv6RecvQueue {
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
            queued_bytes: 0,
        }
    }

    fn push(&mut self, packet: RawIpv6Packet) -> bool {
        let packet_len = packet.bytes.len();
        if self.packets.len() >= RAW_RECV_PACKET_LIMIT
            || self.queued_bytes.saturating_add(packet_len) > RAW_RECV_BYTE_LIMIT
        {
            return false;
        }
        self.queued_bytes += packet_len;
        self.packets.push_back(packet);
        true
    }

    fn pop(&mut self) -> Option<RawIpv6Packet> {
        let packet = self.packets.pop_front()?;
        self.queued_bytes -= packet.bytes.len();
        Some(packet)
    }

    fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

#[derive(Clone, Copy, Debug)]
struct RawIpv6Error {
    destination: Ipv6Address,
    extended: IpExtendedError,
}

struct HdrinclIpv6Packet {
    source: Ipv6Address,
    destination: Ipv6Address,
    next_header: u8,
    traffic_class: u8,
    hop_limit: u8,
    total_len: usize,
}

fn raw_ipv6_protocol(protocol: i32) -> Result<Option<u8>> {
    let protocol = u8::try_from(protocol).map_err(|_| {
        Error::with_message(
            Errno::EPROTONOSUPPORT,
            "raw IPv6 protocol must fit in an 8-bit protocol number",
        )
    })?;
    if protocol == 0 {
        return_errno_with_message!(
            Errno::EPROTONOSUPPORT,
            "IPPROTO_IP is not a valid IPv6 raw protocol"
        );
    }
    if protocol == IPPROTO_RAW {
        return Ok(None);
    }
    Ok(Some(protocol))
}

fn parse_hdrincl_ipv6_packet(packet: &[u8]) -> Result<HdrinclIpv6Packet> {
    if packet.len() < IPV6_HEADER_LEN || packet[0] >> 4 != 6 {
        return_errno_with_message!(Errno::EINVAL, "IPV6_HDRINCL header is invalid");
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN.saturating_add(payload_len);
    if total_len > packet.len() {
        return_errno_with_message!(Errno::EINVAL, "IPV6_HDRINCL payload is truncated");
    }
    let mut source = [0; 16];
    let mut destination = [0; 16];
    source.copy_from_slice(&packet[8..24]);
    destination.copy_from_slice(&packet[24..40]);
    Ok(HdrinclIpv6Packet {
        source: Ipv6Address::new(source),
        destination: Ipv6Address::new(destination),
        next_header: packet[6],
        traffic_class: (packet[0] << 4) | (packet[1] >> 4),
        hop_limit: packet[7],
        total_len,
    })
}

fn raw_ipv6_control_options(
    control_messages: &[ControlMessage],
) -> Result<(Option<u8>, Option<u8>)> {
    let mut hop_limit = None;
    let mut tclass = None;
    for message in control_messages {
        let ControlMessage::IpV6(message) = message else {
            continue;
        };
        match message {
            Ipv6ControlMessage::HopLimit(value) => {
                hop_limit = Some(u8::try_from(*value).map_err(|_| {
                    Error::with_message(Errno::EINVAL, "IPV6_HOPLIMIT must fit in a byte")
                })?);
            }
            Ipv6ControlMessage::TClass(value) => {
                tclass = Some(u8::try_from(*value).map_err(|_| {
                    Error::with_message(Errno::EINVAL, "IPV6_TCLASS must fit in a byte")
                })?);
            }
            Ipv6ControlMessage::ExtendedError(_) => {
                warn!("ignoring receive-only IPv6 error control message on sendmsg");
            }
        }
    }
    Ok((hop_limit, tclass))
}

fn is_icmpv6_echo_request(payload: &[u8]) -> bool {
    payload.len() >= 8 && payload[0] == 128 && payload[1] == 0
}

fn build_ipv6_packet(
    source: Ipv6Address,
    destination: Ipv6Address,
    next_header: u8,
    traffic_class: u8,
    hop_limit: u8,
    payload: &mut [u8],
) -> Vec<u8> {
    let mut packet = vec![0; IPV6_HEADER_LEN + payload.len()];
    packet[0] = 0x60 | (traffic_class >> 4);
    packet[1] = traffic_class << 4;
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet[6] = next_header;
    packet[7] = hop_limit;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[IPV6_HEADER_LEN..].copy_from_slice(payload);
    if next_header == IPPROTO_ICMPV6 && packet.len() >= IPV6_HEADER_LEN + 8 {
        packet[IPV6_HEADER_LEN + 2] = 0;
        packet[IPV6_HEADER_LEN + 3] = 0;
        let checksum = icmpv6_checksum(source, destination, &packet[IPV6_HEADER_LEN..]);
        packet[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4]
            .copy_from_slice(&checksum.to_be_bytes());
    }
    packet
}

fn icmpv6_checksum(source: Ipv6Address, destination: Ipv6Address, payload: &[u8]) -> u16 {
    let mut sum = 0u64;
    for address in [source.octets(), destination.octets()] {
        for word in address.chunks_exact(2) {
            sum = sum.wrapping_add(u64::from(u16::from_be_bytes([word[0], word[1]])));
        }
    }
    sum = sum.wrapping_add((payload.len() as u64) >> 16);
    sum = sum.wrapping_add((payload.len() as u64) & 0xffff);
    sum = sum.wrapping_add(u64::from(IPPROTO_ICMPV6));
    for word in payload.chunks(2) {
        let value = if word.len() == 2 {
            u16::from_be_bytes([word[0], word[1]])
        } else {
            u16::from(word[0]) << 8
        };
        sum = sum.wrapping_add(u64::from(value));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
