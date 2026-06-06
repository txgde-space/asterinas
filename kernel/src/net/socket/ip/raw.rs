// SPDX-License-Identifier: MPL-2.0

use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use aster_bigtcp::{
    socket::SocketEventObserver,
    wire::{IpAddress, IpEndpoint, IpProtocol, Ipv4Address},
};

use super::{
    common::get_ephemeral_endpoint,
    options::{IpOptionSet, SetIpLevelOption},
    raw_observer::RawIpObserver,
};
use crate::{
    events::IoEvents,
    fs::{pseudofs::SockFs, vfs::path::Path},
    net::{
        iface::{RawIpSocket as BigtcpRawIpSocket, iter_all_ifaces},
        socket::{
            Socket,
            options::SocketOption,
            private::SocketPrivate,
            util::{MessageHeader, SendRecvFlags, SocketAddr},
        },
    },
    prelude::*,
    process::{
        credentials::capabilities::CapSet,
        posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable, Pollee},
    },
    util::{MultiRead, MultiWrite, net::Protocol},
};

/// An IPv4 raw socket.
///
/// This initial implementation establishes the Linux ABI and privilege boundary. Packet queues
/// will be connected to `aster-bigtcp` in the next implementation stage.
pub struct RawSocket {
    protocol: Protocol,
    raw_sockets: Vec<BigtcpRawIpSocket>,
    is_nonblocking: AtomicBool,
    ip_options: RwLock<IpOptionSet>,
    pollee: Pollee,
    pseudo_path: Path,
}

impl RawSocket {
    /// Creates an IPv4 raw socket after checking `CAP_NET_RAW`.
    pub fn new(is_nonblocking: bool, protocol: Protocol) -> Result<Arc<Self>> {
        // RAW_SOCKET_STAGE1: Keep the capability check at the creation boundary so no
        // unprivileged file descriptor can later gain raw packet access.
        check_raw_socket_privilege()?;

        let pollee = Pollee::new();
        let raw_sockets = iter_all_ifaces()
            .map(|iface| {
                let observer: Arc<dyn SocketEventObserver> =
                    Arc::new(RawIpObserver::new(pollee.clone()));
                BigtcpRawIpSocket::new(iface.clone(), IpProtocol::Icmp, observer)
            })
            .collect();

        Ok(Arc::new(Self {
            protocol,
            raw_sockets,
            is_nonblocking: AtomicBool::new(is_nonblocking),
            ip_options: RwLock::new(IpOptionSet::new_raw()),
            pollee,
            pseudo_path: SockFs::new_path(),
        }))
    }

    fn try_recv(&self, writer: &mut dyn MultiWrite) -> Result<(usize, SocketAddr)> {
        let packet = self
            .raw_sockets
            .iter()
            .find_map(BigtcpRawIpSocket::recv)
            .ok_or_else(|| Error::with_message(Errno::EAGAIN, "the receive queue is empty"))?;

        let source = packet.source();
        let received_bytes = writer.write(&mut VmReader::from(packet.bytes()))?;
        self.pollee.invalidate();

        Ok((received_bytes, SocketAddr::IPv4(source, 0)))
    }

    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::empty();
        if self.raw_sockets.iter().any(BigtcpRawIpSocket::can_recv) {
            events |= IoEvents::IN;
        }
        if self.raw_sockets.iter().any(BigtcpRawIpSocket::can_send) {
            events |= IoEvents::OUT;
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

        if !control_messages.is_empty() {
            // TODO: Support control messages such as IP_TTL/IP_TOS on raw sockets.
            warn!("sending raw socket control message is not supported");
        }

        let Some(SocketAddr::IPv4(destination, _)) = addr else {
            return_errno_with_message!(
                Errno::EDESTADDRREQ,
                "raw IPv4 sockets require an IPv4 destination address"
            );
        };

        if !matches!(self.protocol, Protocol::IPPROTO_ICMP) {
            return_errno_with_message!(
                Errno::EOPNOTSUPP,
                "only IPPROTO_ICMP raw transmission is currently supported"
            );
        }

        let mut payload = vec![0; reader.sum_lens()];
        let sent_bytes = reader.read(&mut VmWriter::from(payload.as_mut_slice()))?;
        payload.truncate(sent_bytes);

        let destination = if self.ip_options.read().hdrincl() {
            // RAW_SOCKET_STAGE4: `IP_HDRINCL` users provide the IPv4 header.
            // Stage 4 extracts the ICMP payload and route destination while the
            // lower stack still owns final IPv4 header emission.
            let parsed_packet = parse_hdrincl_icmp_packet(&payload)?;
            payload.truncate(parsed_packet.total_len);
            payload.drain(..parsed_packet.header_len);
            parsed_packet.destination
        } else {
            destination
        };

        let remote_endpoint = IpEndpoint::new(IpAddress::Ipv4(destination), 0);
        let local_endpoint = get_ephemeral_endpoint(&remote_endpoint);
        let IpAddress::Ipv4(local_addr) = local_endpoint.addr;

        let raw_socket = self
            .raw_sockets
            .iter()
            .find(|socket| {
                socket
                    .local_ipv4_addr()
                    .is_some_and(|addr| addr == local_addr)
            })
            .ok_or_else(|| Error::with_message(Errno::ENETUNREACH, "no raw socket route"))?;

        // RAW_SOCKET_STAGE3: Userspace supplies the ICMP payload for
        // `IPPROTO_ICMP`; the IPv4 header is still owned by the network stack.
        if !raw_socket.send_ipv4(destination, payload) {
            return_errno_with_message!(Errno::ENOBUFS, "raw socket transmit queue is full");
        }

        self.pollee.invalidate();
        Ok(sent_bytes)
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
    fn addr(&self) -> Result<SocketAddr> {
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0);
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
        _flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        // RAW_SOCKET_STAGE2: Blocking behavior is delegated to the common socket
        // wait path, while queue access itself remains a nonblocking operation.
        let (received_bytes, source) = self.block_on(IoEvents::IN, || self.try_recv(writer))?;
        Ok((received_bytes, MessageHeader::new(Some(source), Vec::new())))
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

struct HdrinclPacket {
    destination: Ipv4Address,
    header_len: usize,
    total_len: usize,
}

fn parse_hdrincl_icmp_packet(packet: &[u8]) -> Result<HdrinclPacket> {
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPV4_VERSION: u8 = 4;
    const ICMP_PROTOCOL: u8 = 1;

    if packet.len() < IPV4_MIN_HEADER_LEN {
        return_errno_with_message!(Errno::EINVAL, "IP_HDRINCL packet is too short");
    }

    let version = packet[0] >> 4;
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if version != IPV4_VERSION || header_len < IPV4_MIN_HEADER_LEN || header_len > packet.len() {
        return_errno_with_message!(Errno::EINVAL, "IP_HDRINCL IPv4 header is invalid");
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || total_len > packet.len() {
        return_errno_with_message!(Errno::EINVAL, "IP_HDRINCL total length is invalid");
    }

    if packet[9] != ICMP_PROTOCOL {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "only IPPROTO_ICMP IP_HDRINCL packets are supported"
        );
    }

    Ok(HdrinclPacket {
        destination: Ipv4Address::new(packet[16], packet[17], packet[18], packet[19]),
        header_len,
        total_len,
    })
}

fn check_raw_socket_privilege() -> Result<()> {
    let credentials = {
        let thread = current_thread!();
        let posix_thread = thread.as_posix_thread().unwrap();
        posix_thread.credentials()
    };

    if credentials.effective_capset().contains(CapSet::NET_RAW) {
        return Ok(());
    }

    return_errno_with_message!(
        Errno::EACCES,
        "only threads with CAP_NET_RAW can create raw sockets"
    );
}
