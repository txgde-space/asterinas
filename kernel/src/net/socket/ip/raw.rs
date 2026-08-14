// SPDX-License-Identifier: MPL-2.0

use alloc::collections::VecDeque;
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use aster_bigtcp::{
    socket::SocketEventObserver,
    wire::{IpAddress, IpEndpoint, IpProtocol, Ipv4Address},
};

use super::{
    common::{get_ephemeral_endpoint, get_iface_to_bind},
    options::{IpOptionSet, SetIpLevelOption},
    raw_observer::RawIpObserver,
};
use crate::{
    events::IoEvents,
    fs::{pseudofs::SockFs, vfs::path::Path},
    net::{
        iface::{RawIpSocket as BigtcpRawIpSocket, iter_all_ifaces},
        router::lookup_ipv4_iface,
        socket::{
            Socket,
            options::SocketOption,
            private::SocketPrivate,
            util::{
                ControlMessage, IpControlMessage, IpExtendedError, MessageHeader, SendRecvFlags,
                SocketAddr,
            },
        },
    },
    prelude::*,
    process::{
        credentials::capabilities::CapSet,
        posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable, Pollee},
    },
    util::{MultiRead, MultiWrite},
};

/// An IPv4 raw socket.
///
/// 该 Socket 为每个已注册 IPv4 接口持有一个 `aster-bigtcp` Raw 队列；
/// 队列在入口和出口方向都保留请求的协议号。
pub struct RawSocket {
    /// `None` 表示 Linux 的 IPPROTO_RAW 任意协议发送 Socket。
    protocol: Option<IpProtocol>,
    raw_sockets: Vec<BigtcpRawIpSocket>,
    local_endpoint: RwLock<Option<IpEndpoint>>,
    remote_endpoint: RwLock<Option<IpEndpoint>>,
    is_nonblocking: AtomicBool,
    ip_options: RwLock<IpOptionSet>,
    error_queue: RwLock<VecDeque<RawSocketError>>,
    pollee: Pollee,
    pseudo_path: Path,
}

impl RawSocket {
    /// Creates an IPv4 raw socket after checking `CAP_NET_RAW`.
    pub fn new(is_nonblocking: bool, protocol: i32) -> Result<Arc<Self>> {
        // RAW_SOCKET_STAGE1: Keep the capability check at the creation boundary so no
        // unprivileged file descriptor can later gain raw packet access.
        check_raw_socket_privilege()?;

        let protocol = raw_ip_protocol(protocol)?;
        let registered_protocol = protocol.unwrap_or(IpProtocol::Unknown(255));

        let pollee = Pollee::new();
        let raw_sockets = iter_all_ifaces()
            .map(|iface| {
                let observer: Arc<dyn SocketEventObserver> =
                    Arc::new(RawIpObserver::new(pollee.clone()));
                BigtcpRawIpSocket::new(iface.clone(), registered_protocol, observer)
            })
            .collect();

        Ok(Arc::new(Self {
            protocol,
            raw_sockets,
            local_endpoint: RwLock::new(None),
            remote_endpoint: RwLock::new(None),
            is_nonblocking: AtomicBool::new(is_nonblocking),
            ip_options: RwLock::new(IpOptionSet::new_raw()),
            error_queue: RwLock::new(VecDeque::new()),
            pollee,
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
                .ok_or_else(|| Error::with_message(Errno::EAGAIN, "the error queue is empty"))?;
            self.pollee.invalidate();
            return Ok((
                0,
                MessageHeader::new(
                    Some(SocketAddr::IPv4(error.destination, 0)),
                    vec![ControlMessage::Ip(IpControlMessage::ExtendedError(
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
            .raw_sockets
            .iter()
            .find_map(BigtcpRawIpSocket::recv)
            .ok_or_else(|| Error::with_message(Errno::EAGAIN, "the receive queue is empty"))?;

        let source = packet.source();
        let received_bytes = writer.write(&mut VmReader::from(packet.bytes()))?;
        self.pollee.invalidate();

        Ok((
            received_bytes,
            MessageHeader::new(Some(SocketAddr::IPv4(source, 0)), Vec::new()),
        ))
    }

    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::empty();
        if self.protocol.is_some() && self.raw_sockets.iter().any(BigtcpRawIpSocket::can_recv) {
            events |= IoEvents::IN;
        }
        if self.raw_sockets.iter().any(BigtcpRawIpSocket::can_send) {
            events |= IoEvents::OUT;
        }
        if !self.error_queue.read().is_empty() {
            events |= IoEvents::ERR;
        }
        events
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        if !flags.is_all_supported() {
            warn!("unsupported flags: {:?}", flags);
        }

        let MessageHeader {
            addr,
            control_messages,
        } = message_header;

        let (control_tos, control_ttl) = raw_control_options(&control_messages)?;

        let destination = match addr {
            Some(SocketAddr::IPv4(destination, _)) => destination,
            Some(_) => {
                return_errno_with_message!(
                    Errno::EAFNOSUPPORT,
                    "raw IPv4 sockets require an IPv4 destination address"
                )
            }
            None => {
                let endpoint = self.remote_endpoint.read().ok_or_else(|| {
                    Error::with_message(
                        Errno::EDESTADDRREQ,
                        "raw IPv4 sockets require an IPv4 destination address",
                    )
                })?;
                let IpAddress::Ipv4(destination) = endpoint.addr else {
                    return_errno_with_message!(
                        Errno::EAFNOSUPPORT,
                        "raw IPv4 sockets require an IPv4 destination address"
                    );
                };
                destination
            }
        };

        let mut payload = vec![0; reader.sum_lens()];
        let sent_bytes = reader.read(&mut VmWriter::from(payload.as_mut_slice()))?;
        payload.truncate(sent_bytes);

        let options = *self.ip_options.read();
        let parsed_header = if options.hdrincl() {
            // RAW_SOCKET_STAGE4: `IP_HDRINCL` users provide the IPv4 header.
            let parsed_packet = parse_hdrincl_ipv4_packet(&payload)?;
            if self.protocol.is_some_and(|protocol| protocol != parsed_packet.protocol) {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "IP_HDRINCL protocol does not match the raw socket"
                );
            }
            payload.truncate(parsed_packet.total_len);
            payload.drain(..parsed_packet.header_len);
            Some(parsed_packet)
        } else {
            None
        };

        let destination = parsed_header
            .as_ref()
            .map_or(destination, |packet| packet.destination);
        let protocol = parsed_header.as_ref().map_or_else(
            || {
                self.protocol.ok_or_else(|| {
                    Error::with_message(
                        Errno::EINVAL,
                        "IPPROTO_RAW requires IP_HDRINCL to select a protocol",
                    )
                })
            },
            |packet| Ok(packet.protocol),
        )?;

        if destination == Ipv4Address::UNSPECIFIED {
            self.queue_local_error(destination, Errno::ENETUNREACH);
            return_errno_with_message!(Errno::ENETUNREACH, "the IPv4 destination is unspecified");
        }

        if lookup_ipv4_iface(destination, None).is_none() {
            self.queue_local_error(destination, Errno::ENETUNREACH);
            return_errno_with_message!(Errno::ENETUNREACH, "no IPv4 route to destination");
        }

        let remote_endpoint = IpEndpoint::new(IpAddress::Ipv4(destination), 0);
        let local_endpoint = self
            .local_endpoint
            .read()
            .unwrap_or_else(|| get_ephemeral_endpoint(&remote_endpoint));
        let IpAddress::Ipv4(local_addr) = local_endpoint.addr else {
            return_errno_with_message!(
                Errno::EAFNOSUPPORT,
                "raw IPv4 sockets require an IPv4 local address"
            );
        };
        let source = parsed_header
            .as_ref()
            .map_or(local_addr, |packet| {
                if packet.source == Ipv4Address::UNSPECIFIED {
                    local_addr
                } else {
                    packet.source
                }
            });
        let traffic_class = parsed_header.as_ref().map_or(
            control_tos.unwrap_or(options.tos()),
            |packet| packet.traffic_class,
        );
        let hop_limit = parsed_header.as_ref().map_or(
            control_ttl.unwrap_or(options.ttl().get()),
            |packet| packet.hop_limit,
        );

        let Some(raw_socket) = self
            .raw_sockets
            .iter()
            .find(|socket| {
                socket
                    .local_ipv4_addr()
                    .is_some_and(|addr| addr == local_addr)
            })
        else {
            self.queue_local_error(destination, Errno::ENETUNREACH);
            return_errno_with_message!(Errno::ENETUNREACH, "no raw socket route");
        };

        // 用户态提供协议载荷；除非请求了 IP_HDRINCL，否则 IPv4 头仍由网络栈负责。
        if !raw_socket.send_ipv4(
            destination,
            source,
            protocol,
            traffic_class,
            hop_limit,
            payload,
        ) {
            self.queue_local_error(destination, Errno::ENOBUFS);
            return_errno_with_message!(Errno::ENOBUFS, "raw socket transmit queue is full");
        }

        self.pollee.invalidate();
        Ok(sent_bytes)
    }

    fn queue_local_error(&self, destination: Ipv4Address, errno: Errno) {
        if !self.ip_options.read().recverr() {
            return;
        }

        const SO_EE_ORIGIN_LOCAL: u8 = 1;
        const MAX_ERROR_QUEUE: usize = 16;
        let mut queue = self.error_queue.write();
        if queue.len() >= MAX_ERROR_QUEUE {
            queue.pop_front();
        }
        queue.push_back(RawSocketError {
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
}

impl Pollable for RawSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }
}

impl SocketPrivate for RawSocket {
    fn is_nonblocking(&self) -> bool {
        self.is_nonblocking.load(Ordering::Relaxed)
    }

    fn set_nonblocking(&self, is_nonblocking: bool) {
        self.is_nonblocking.store(is_nonblocking, Ordering::Relaxed);
    }
}

impl Socket for RawSocket {
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let endpoint: IpEndpoint = socket_addr.try_into()?;

        if get_iface_to_bind(&endpoint.addr).is_none() {
            return_errno_with_message!(
                Errno::EADDRNOTAVAIL,
                "the address is not available from the local machine"
            );
        }

        // Linux raw socket bind() 只固定本地 IPv4 地址，端口字段对 ICMP raw socket 无意义。
        *self.local_endpoint.write() = Some(IpEndpoint::new(endpoint.addr, 0));
        Ok(())
    }

    fn connect(&self, socket_addr: SocketAddr) -> Result<()> {
        let SocketAddr::IPv4(destination, _) = socket_addr else {
            return_errno_with_message!(
                Errno::EAFNOSUPPORT,
                "raw IPv4 sockets only support IPv4 peers"
            );
        };

        // Linux raw socket connect() 会保存默认对端；iputils ping 会先走这条路径，
        // 随后用 send()/write() 发送不带目标地址的 ICMP 报文。
        *self.remote_endpoint.write() = Some(IpEndpoint::new(IpAddress::Ipv4(destination), 0));
        Ok(())
    }

    fn addr(&self) -> Result<SocketAddr> {
        let endpoint = self
            .local_endpoint
            .read()
            .unwrap_or_else(|| IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0));
        Ok(endpoint.into())
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let endpoint = self.remote_endpoint.read().ok_or_else(|| {
            Error::with_message(Errno::ENOTCONN, "the raw socket is not connected")
        })?;
        Ok(endpoint.into())
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
        // RAW_SOCKET_STAGE2: Blocking behavior is delegated to the common socket
        // wait path, while queue access itself remains a nonblocking operation.
        let events = if flags.contains(SendRecvFlags::MSG_ERRQUEUE) {
            IoEvents::ERR
        } else {
            IoEvents::IN
        };
        self.block_on(events, || self.try_recv(writer, flags))
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        self.ip_options.read().get_option(option)
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        self.ip_options.write().set_option(option, self)?;
        Ok(())
    }

    fn pseudo_path(&self) -> &Path {
        &self.pseudo_path
    }
}

impl SetIpLevelOption for RawSocket {
    fn set_hdrincl(&self, _hdrincl: bool) -> Result<()> {
        // RAW_SOCKET_STAGE4: Raw IPv4 sockets are the only IPv4 sockets in this
        // stack that may accept user-provided IP headers.
        Ok(())
    }
}

impl fmt::Debug for RawSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawSocket")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
struct RawSocketError {
    destination: Ipv4Address,
    extended: IpExtendedError,
}

struct HdrinclPacket {
    destination: Ipv4Address,
    source: Ipv4Address,
    protocol: IpProtocol,
    traffic_class: u8,
    hop_limit: u8,
    header_len: usize,
    total_len: usize,
}

fn parse_hdrincl_ipv4_packet(packet: &[u8]) -> Result<HdrinclPacket> {
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPV4_VERSION: u8 = 4;

    if packet.len() < IPV4_MIN_HEADER_LEN {
        return_errno_with_message!(Errno::EINVAL, "IP_HDRINCL packet is too short");
    }

    let version = packet[0] >> 4;
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if version != IPV4_VERSION || header_len < IPV4_MIN_HEADER_LEN || header_len > packet.len() {
        return_errno_with_message!(Errno::EINVAL, "IP_HDRINCL IPv4 header is invalid");
    }
    if header_len != IPV4_MIN_HEADER_LEN {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "IP_HDRINCL IPv4 options are not supported yet"
        );
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || total_len > packet.len() {
        return_errno_with_message!(Errno::EINVAL, "IP_HDRINCL total length is invalid");
    }

    Ok(HdrinclPacket {
        destination: Ipv4Address::new(packet[16], packet[17], packet[18], packet[19]),
        source: Ipv4Address::new(packet[12], packet[13], packet[14], packet[15]),
        protocol: ip_protocol_from_number(packet[9]),
        traffic_class: packet[1],
        hop_limit: packet[8],
        header_len,
        total_len,
    })
}

fn raw_ip_protocol(protocol: i32) -> Result<Option<IpProtocol>> {
    let protocol = u8::try_from(protocol).map_err(|_| {
        Error::with_message(
            Errno::EPROTONOSUPPORT,
            "raw IPv4 protocol must fit in an 8-bit IP protocol number",
        )
    })?;

    if protocol == 0 {
        return_errno_with_message!(
            Errno::EPROTONOSUPPORT,
            "IPPROTO_IP is not a valid fixed-protocol raw socket"
        );
    }

    if protocol == 255 {
        return Ok(None);
    }

    Ok(Some(ip_protocol_from_number(protocol)))
}

fn ip_protocol_from_number(protocol: u8) -> IpProtocol {
    match protocol {
        1 => IpProtocol::Icmp,
        2 => IpProtocol::Igmp,
        6 => IpProtocol::Tcp,
        17 => IpProtocol::Udp,
        value => IpProtocol::Unknown(value),
    }
}

/// 解析每次发送使用的 IPv4 辅助选项。存在 `IP_HDRINCL` 时仍以其为准，
/// 因此这些值只用于网络栈正常生成 IPv4 头的路径。
fn raw_control_options(control_messages: &[ControlMessage]) -> Result<(Option<u8>, Option<u8>)> {
    let mut tos = None;
    let mut ttl = None;

    for message in control_messages {
        let ControlMessage::Ip(message) = message else {
            continue;
        };

        match message {
            IpControlMessage::Tos(value) => {
                tos = Some(u8::try_from(*value).map_err(|_| {
                    Error::with_message(Errno::EINVAL, "IP_TOS must fit in an unsigned byte")
                })?);
            }
            IpControlMessage::Ttl(value) => {
                let value = u8::try_from(*value).map_err(|_| {
                    Error::with_message(Errno::EINVAL, "IP_TTL must fit in an unsigned byte")
                })?;
                if value == 0 {
                    return_errno_with_message!(Errno::EINVAL, "IP_TTL must be non-zero");
                }
                ttl = Some(value);
            }
            IpControlMessage::ExtendedError(_) => {
                warn!("ignoring receive-only IP_RECVERR control message on sendmsg");
            }
        }
    }

    Ok((tos, ttl))
}

pub(super) fn check_raw_socket_privilege() -> Result<()> {
    let credentials = {
        let thread = current_thread!();
        let posix_thread = thread.as_posix_thread().unwrap();
        posix_thread.credentials()
    };

    if credentials.euid().is_root() || credentials.effective_capset().contains(CapSet::NET_RAW) {
        return Ok(());
    }

    return_errno_with_message!(
        Errno::EACCES,
        "only root or threads with CAP_NET_RAW can create raw sockets"
    );
}
