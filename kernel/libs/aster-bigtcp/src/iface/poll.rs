// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;

use smoltcp::{
    iface::{
        Context,
        packet::{IpPayload, Packet, icmp_reply_payload_len},
    },
    phy::{ChecksumCapabilities, Device, RxToken, TxToken},
    wire::{
        IPV4_HEADER_LEN, IPV4_MIN_MTU, Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, IpAddress,
        IpProtocol, IpRepr, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
        UdpPacket, UdpRepr,
    },
};

use super::poll_iface::PollableIfaceMut;
use crate::{
    ext::Ext,
    netfilter::{self, HookPoint, Ipv4PacketContext},
    forwarding::{ForwardedIpv4Packet, ForwardingResult},
    socket::{RawIpv4TxPacket, TcpConnectionBg, TcpProcessResult},
    socket_table::{ConnectionKey, ListenerKey, SocketTable},
};

pub(super) struct PollContext<'a, E: Ext> {
    iface: PollableIfaceMut<'a, E>,
    sockets: &'a SocketTable<E>,
    actions: &'a mut Vec<SocketTableAction<E>>,
    ingress_ifindex: u32,
}

/// Socket table actions such as adding or removing TCP connections.
///
/// Note that they must be performed in order. This is because the same connection key can occur
/// multiple times, but with different types of operations (e.g., add or remove).
pub(super) enum SocketTableAction<E: Ext> {
    AddTcpConn(Arc<TcpConnectionBg<E>>),
    DelTcpConn(ConnectionKey),
}

impl<'a, E: Ext> PollContext<'a, E> {
    pub(super) fn new(
        iface: PollableIfaceMut<'a, E>,
        sockets: &'a SocketTable<E>,
        actions: &'a mut Vec<SocketTableAction<E>>,
        ingress_ifindex: u32,
    ) -> Self {
        Self {
            iface,
            sockets,
            actions,
            ingress_ifindex,
        }
    }
}

// This works around <https://github.com/rust-lang/rust/issues/49601>.
// See the issue above for details.
pub(super) trait FnHelper<A, B, C, O>: FnMut(A, B, C) -> O {}
impl<A, B, C, O, F> FnHelper<A, B, C, O> for F where F: FnMut(A, B, C) -> O {}

impl<E: Ext> PollContext<'_, E> {
    pub(super) fn poll_ingress<D, P, Q>(
        &mut self,
        device: &mut D,
        process_phy: &mut P,
        dispatch_phy: &mut Q,
    ) where
        D: Device + ?Sized,
        P: for<'pkt, 'cx, 'tx> FnHelper<
                &'pkt [u8],
                &'cx mut Context,
                D::TxToken<'tx>,
                Option<(Ipv4Packet<&'pkt [u8]>, D::TxToken<'tx>)>,
            >,
        Q: FnMut(&Packet, &mut Context, D::TxToken<'_>),
    {
        while let Some((rx_token, tx_token)) = device.receive(self.iface.context().now()) {
            rx_token.consume(|data| {
                let Some((pkt, tx_token)) = process_phy(data, self.iface.context_mut(), tx_token)
                else {
                    return;
                };

                let Some(reply) = self.parse_and_process_ipv4(pkt) else {
                    return;
                };

                self.dispatch_outgoing_packet(&reply, dispatch_phy, tx_token);
            });
        }
    }

    /// Drains packets accepted by the router into the egress device.
    ///
    /// Packets are copied into a bounded queue before this point so the ingress
    /// device lock is never held while an unrelated interface transmits.
    pub(super) fn poll_forwarded_egress<D, Q>(
        &mut self,
        device: &mut D,
        forwarded_packets: &SpinLock<VecDeque<ForwardedIpv4Packet>, BottomHalfDisabled>,
        dispatch_forwarded_phy: &mut Q,
    ) where
        D: Device + ?Sized,
        Q: FnMut(&ForwardedIpv4Packet, &mut Context, D::TxToken<'_>) -> bool,
    {
        while let Some(tx_token) = device.transmit(self.iface.context().now()) {
            let Some(mut packet) = forwarded_packets.lock().pop_front() else {
                break;
            };

            if !self.accept_ipv4_at(HookPoint::PostRouting, &packet.ip_repr) {
                continue;
            }

            if !packet.postrouting_nat_applied() {
                netfilter::rewrite_forwarded_ipv4_postrouting(
                    &mut packet.ip_repr,
                    &mut packet.payload,
                    self.iface.context().ipv4_addr(),
                );
                packet.mark_postrouting_nat_applied();
            }

            if !dispatch_forwarded_phy(&packet, self.iface.context_mut(), tx_token) {
                // Ethernet ARP resolution consumed the transmit token. Keep
                // the packet at the head of the bounded queue so that the
                // ARP reply's receive poll can transmit this original packet
                // instead of relying on an upper-layer retransmission.
                forwarded_packets.lock().push_front(packet);
                break;
            }
        }
    }

    fn accept_ipv4_at(&self, hook_point: HookPoint, repr: &Ipv4Repr) -> bool {
        netfilter::evaluate_ipv4(Ipv4PacketContext::new(hook_point, repr)).is_accept()
    }

    fn accept_ip_repr_at(&self, hook_point: HookPoint, repr: &IpRepr) -> bool {
        let IpRepr::Ipv4(ipv4_repr) = repr;

        self.accept_ipv4_at(hook_point, ipv4_repr)
    }

    fn accept_packet_at(&self, hook_point: HookPoint, packet: &Packet<'_>) -> bool {
        self.accept_ip_repr_at(hook_point, &packet.ip_repr())
    }

    fn accept_icmpv4_at(
        &self,
        hook_point: HookPoint,
        repr: &IpRepr,
        icmp_repr: &Icmpv4Repr<'_>,
    ) -> bool {
        let IpRepr::Ipv4(ipv4_repr) = repr;

        netfilter::evaluate_ipv4_icmpv4(Ipv4PacketContext::new(hook_point, ipv4_repr), icmp_repr)
            .is_accept()
    }

    fn accept_tcp_at(&self, hook_point: HookPoint, repr: &IpRepr, tcp_repr: &TcpRepr<'_>) -> bool {
        let IpRepr::Ipv4(ipv4_repr) = repr;

        netfilter::evaluate_ipv4_tcp(Ipv4PacketContext::new(hook_point, ipv4_repr), tcp_repr)
            .is_accept()
    }

    fn accept_udp_at(&self, hook_point: HookPoint, repr: &IpRepr, udp_repr: &UdpRepr) -> bool {
        let IpRepr::Ipv4(ipv4_repr) = repr;

        netfilter::evaluate_ipv4_udp(Ipv4PacketContext::new(hook_point, ipv4_repr), udp_repr)
            .is_accept()
    }

    fn rewrite_tcp_postrouting<'p>(
        &self,
        ip_repr: IpRepr,
        tcp_repr: TcpRepr<'p>,
    ) -> (IpRepr, TcpRepr<'p>) {
        match ip_repr {
            IpRepr::Ipv4(ipv4_repr) => {
                let (ipv4_repr, tcp_repr) = netfilter::rewrite_ipv4_tcp_postrouting(
                    ipv4_repr,
                    tcp_repr,
                    self.iface.context().ipv4_addr(),
                );

                (IpRepr::Ipv4(ipv4_repr), tcp_repr)
            }
        }
    }

    fn rewrite_udp_postrouting(&self, ip_repr: IpRepr, udp_repr: UdpRepr) -> (IpRepr, UdpRepr) {
        match ip_repr {
            IpRepr::Ipv4(ipv4_repr) => {
                let (ipv4_repr, udp_repr) = netfilter::rewrite_ipv4_udp_postrouting(
                    ipv4_repr,
                    udp_repr,
                    self.iface.context().ipv4_addr(),
                );

                (IpRepr::Ipv4(ipv4_repr), udp_repr)
            }
        }
    }

    fn rewrite_icmp_postrouting(&self, ipv4_repr: Ipv4Repr) -> Ipv4Repr {
        netfilter::rewrite_ipv4_icmp_postrouting(ipv4_repr, self.iface.context().ipv4_addr())
    }

    fn dispatch_outgoing_packet<T, Q>(
        &mut self,
        packet: &Packet<'_>,
        dispatch_phy: &mut Q,
        tx_token: T,
    ) where
        T: TxToken,
        Q: FnMut(&Packet, &mut Context, T),
    {
        // IPv4 出站包先经过 LOCAL_OUT/POSTROUTING；没有规则时保持原行为。
        if !self.accept_packet_at(HookPoint::LocalOut, packet)
            || !self.accept_packet_at(HookPoint::PostRouting, packet)
        {
            return;
        }

        dispatch_phy(packet, self.iface.context_mut(), tx_token);
    }

    fn parse_and_process_ipv4<'pkt>(
        &mut self,
        pkt: Ipv4Packet<&'pkt [u8]>,
    ) -> Option<Packet<'pkt>> {
        // Parse the IP header. Ignore the packet if the header is ill-formed.
        let mut repr = Ipv4Repr::parse(&pkt, &self.iface.context().checksum_caps()).ok()?;

        if !self.accept_ipv4_at(HookPoint::PreRouting, &repr) {
            return None;
        }

        // NAT PREROUTING runs before the local-delivery versus forwarding
        // decision. This permits DNAT to select a routed backend and permits
        // a tracked reply addressed to the router to re-enter forwarding.
        // The ingress DMA buffer is immutable here.  Keep a private forwarded
        // payload so NAT can rewrite TCP/UDP ports and checksums before the
        // packet is queued, while local delivery still observes its original
        // wire representation.
        let mut forwarded_payload = pkt.payload().to_vec();
        netfilter::rewrite_forwarded_ipv4_prerouting(&mut repr, &mut forwarded_payload);

        if !repr.dst_addr.is_broadcast() && !self.is_unicast_local(IpAddress::Ipv4(repr.dst_addr)) {
            if !self.accept_ipv4_at(HookPoint::Forward, &repr)
                || !self.accept_forwarded_transport(&repr, &forwarded_payload)
            {
                return None;
            }

            let result = E::forward_ipv4_packet(
                self.ingress_ifindex,
                ForwardedIpv4Packet::new(repr, forwarded_payload),
            );

            return match result {
                ForwardingResult::Queued => None,
                // Stage 2B deliberately returns the existing host-unreachable
                // response until the later ICMP-error work adds distinct
                // no-route, queue-pressure, and time-exceeded responses.
                ForwardingResult::Disabled
                | ForwardingResult::NoRoute
                | ForwardingResult::HopLimitExceeded
                | ForwardingResult::QueueFull => self.generate_icmp_unreachable(
                    &IpRepr::Ipv4(repr),
                    pkt.payload(),
                    Icmpv4DstUnreachable::HostUnreachable,
                ),
            };
        }

        if !self.accept_ipv4_at(HookPoint::LocalIn, &repr) {
            return None;
        }

        let checksum_caps = self.iface.context().checksum_caps();
        let next_header = repr.next_header;
        let ip_repr = IpRepr::Ipv4(repr);
        let IpRepr::Ipv4(ipv4_repr) = &ip_repr;

        // Deliver the complete IPv4 datagram to matching raw sockets before
        // transport-specific parsing.  This is important for TCP/UDP raw
        // sockets and for experimental protocol numbers: a malformed or
        // otherwise unsupported transport must not make the IP raw receive
        // path disappear.
        self.process_raw_ipv4(ipv4_repr, pkt.as_ref());

        match next_header {
            IpProtocol::Tcp => {
                let tcp_pkt = TcpPacket::new_checked(pkt.payload()).ok()?;
                let tcp_repr = TcpRepr::parse(
                    &tcp_pkt,
                    &ip_repr.src_addr(),
                    &ip_repr.dst_addr(),
                    &checksum_caps,
                )
                .ok()?;
                if !self.accept_tcp_at(HookPoint::LocalIn, &ip_repr, &tcp_repr) {
                    return None;
                }
                self.parse_and_process_tcp(&ip_repr, pkt.payload(), &checksum_caps)
            }
            IpProtocol::Udp => {
                let udp_pkt = UdpPacket::new_checked(pkt.payload()).ok()?;
                let udp_repr = UdpRepr::parse(
                    &udp_pkt,
                    &ip_repr.src_addr(),
                    &ip_repr.dst_addr(),
                    &checksum_caps,
                )
                .ok()?;
                if !self.accept_udp_at(HookPoint::LocalIn, &ip_repr, &udp_repr) {
                    return None;
                }
                self.parse_and_process_udp(&ip_repr, pkt.payload(), &checksum_caps)
            }
            IpProtocol::Icmp => {
                let icmp_packet = Icmpv4Packet::new_checked(pkt.payload()).ok()?;
                let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &checksum_caps).ok()?;
                if !self.accept_icmpv4_at(HookPoint::LocalIn, &ip_repr, &icmp_repr) {
                    return None;
                }
                self.parse_and_process_icmpv4(&ip_repr, pkt.payload(), &checksum_caps)
            }
            _ => None,
        }
    }

    fn accept_forwarded_transport(&self, ipv4_repr: &Ipv4Repr, payload: &[u8]) -> bool {
        let ip_repr = IpRepr::Ipv4(*ipv4_repr);
        let checksum_caps = self.iface.context().checksum_caps();

        match ipv4_repr.next_header {
            IpProtocol::Tcp => TcpPacket::new_checked(payload)
                .ok()
                .and_then(|packet| {
                    TcpRepr::parse(
                        &packet,
                        &ip_repr.src_addr(),
                        &ip_repr.dst_addr(),
                        &checksum_caps,
                    )
                    .ok()
                })
                .is_some_and(|tcp_repr| self.accept_tcp_at(HookPoint::Forward, &ip_repr, &tcp_repr)),
            IpProtocol::Udp => UdpPacket::new_checked(payload)
                .ok()
                .and_then(|packet| {
                    UdpRepr::parse(
                        &packet,
                        &ip_repr.src_addr(),
                        &ip_repr.dst_addr(),
                        &checksum_caps,
                    )
                    .ok()
                })
                .is_some_and(|udp_repr| self.accept_udp_at(HookPoint::Forward, &ip_repr, &udp_repr)),
            IpProtocol::Icmp => Icmpv4Packet::new_checked(payload)
                .ok()
                .and_then(|packet| Icmpv4Repr::parse(&packet, &checksum_caps).ok())
                .is_some_and(|icmp_repr| {
                    self.accept_icmpv4_at(HookPoint::Forward, &ip_repr, &icmp_repr)
                }),
            // Stage 2 forwards only parsed TCP, UDP, and ICMPv4 packets.  This
            // prevents an unknown protocol from bypassing the filter framework.
            _ => false,
        }
    }

    fn process_raw_ipv4(&self, ipv4_repr: &Ipv4Repr, packet: &[u8]) {
        for socket in self.sockets.raw_ip_socket_iter() {
            if socket.protocol() != ipv4_repr.next_header {
                continue;
            }

            socket.process_ipv4(packet, ipv4_repr.src_addr);
        }
    }

    fn process_locally_generated_raw_ipv4(&self, packet: &Packet<'_>) {
        let ip_repr = packet.ip_repr();
        let IpRepr::Ipv4(ipv4_repr) = &ip_repr;

        let mut bytes = vec![0; ip_repr.buffer_len()];
        // raw socket 交付给用户态的是完整 IPv4 报文，不能暴露 loopback/offload
        // 路径中的“忽略校验和”内部表示，否则 iputils ping 会判定 BAD CHECKSUM。
        let checksum_caps = ChecksumCapabilities::default();
        let mut user_visible_caps = self.iface.context().caps.clone();
        user_visible_caps.checksum = checksum_caps.clone();

        ip_repr.emit(&mut bytes, &checksum_caps);
        packet.emit_payload(
            &ip_repr,
            &mut bytes[ip_repr.header_len()..],
            &user_visible_caps,
        );

        if !self.accept_ipv4_at(HookPoint::LocalIn, ipv4_repr) {
            return;
        }

        self.process_raw_ipv4(ipv4_repr, &bytes);
    }

    fn process_locally_generated_raw_ipv4_tx(&self, packet: &RawIpv4TxPacket) {
        let ipv4_repr = packet.ipv4_repr();
        if !self.accept_ipv4_at(HookPoint::LocalIn, &ipv4_repr) {
            return;
        }

        let mut bytes = vec![0; packet.buffer_len()];
        packet.emit_ipv4(&mut bytes, &ChecksumCapabilities::default());
        self.process_raw_ipv4(&ipv4_repr, &bytes);
    }

    fn parse_and_process_tcp<'pkt>(
        &mut self,
        ip_repr: &IpRepr,
        ip_payload: &'pkt [u8],
        checksum_caps: &ChecksumCapabilities,
    ) -> Option<Packet<'pkt>> {
        // TCP connections can only be established between unicast addresses. Ignore the packet if
        // this is not the case. See
        // <https://datatracker.ietf.org/doc/html/rfc9293#section-3.9.2.3>.
        if !ip_repr.src_addr().is_unicast() || !ip_repr.dst_addr().is_unicast() {
            return None;
        }

        // Parse the TCP header. Ignore the packet if the header is ill-formed.
        let tcp_pkt = TcpPacket::new_checked(ip_payload).ok()?;
        let tcp_repr = TcpRepr::parse(
            &tcp_pkt,
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            checksum_caps,
        )
        .ok()?;

        let (ip_repr, tcp_repr) = self.process_tcp_until_outgoing(ip_repr, &tcp_repr)?;
        if !self.accept_tcp_at(HookPoint::LocalOut, &ip_repr, &tcp_repr) {
            return None;
        }

        let (ip_repr, tcp_repr) = self.rewrite_tcp_postrouting(ip_repr, tcp_repr);
        Some(Packet::new(ip_repr, IpPayload::Tcp(tcp_repr)))
    }

    fn process_tcp_until_outgoing(
        &mut self,
        ip_repr: &IpRepr,
        tcp_repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        let (mut ip_repr, mut tcp_repr) = self.process_tcp(ip_repr, tcp_repr)?;

        loop {
            if !self.is_unicast_local(ip_repr.dst_addr()) {
                return Some((ip_repr, tcp_repr));
            }

            let (new_ip_repr, new_tcp_repr) = self.process_tcp(&ip_repr, &tcp_repr)?;
            ip_repr = new_ip_repr;
            tcp_repr = new_tcp_repr;
        }
    }

    fn process_tcp(
        &mut self,
        ip_repr: &IpRepr,
        tcp_repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        // Process packets belonging to existing connections first.
        // Note that we must do this first because SYN packets may match existing TIME-WAIT
        // sockets. See comments in `TcpConnectionBg::process` for details.
        let connection_key = ConnectionKey::new(
            ip_repr.dst_addr(),
            tcp_repr.dst_port,
            ip_repr.src_addr(),
            tcp_repr.src_port,
        );
        let mut connection_in_table = self.sockets.lookup_connection(&connection_key);

        loop {
            // First try the connection in the socket table, as this is the most common. If it
            // fails, it might mean that the connection is dead, the next step is to try the new
            // connections instead.
            let (should_break, connection) = if let Some(conn) = connection_in_table.take() {
                (false, Some(conn))
            } else {
                // Find in reverse order because old connections must have been dead.
                (
                    true,
                    self.actions
                        .iter()
                        .rev()
                        .flat_map(|action| match action {
                            SocketTableAction::AddTcpConn(conn) => Some(conn),
                            SocketTableAction::DelTcpConn(_) => None,
                        })
                        .find(|conn| conn.connection_key() == &connection_key),
                )
            };

            if let Some(connection) = connection {
                let (process_result, became_dead) =
                    connection.process(&mut self.iface, ip_repr, tcp_repr);
                if *became_dead {
                    self.actions
                        .push(SocketTableAction::DelTcpConn(*connection.connection_key()));
                }
                match process_result {
                    TcpProcessResult::NotProcessed => {}
                    TcpProcessResult::Processed => return None,
                    TcpProcessResult::ProcessedWithReply(ip_repr, tcp_repr) => {
                        return Some((ip_repr, tcp_repr));
                    }
                }
            }

            if should_break {
                break;
            }
        }

        // Process packets that request to create new connections second.
        if tcp_repr.control == TcpControl::Syn && tcp_repr.ack_number.is_none() {
            let listener_key = ListenerKey::new(ip_repr.dst_addr(), tcp_repr.dst_port);
            if let Some(listener) = self.sockets.lookup_listener(&listener_key) {
                let (processed, new_tcp_conn) =
                    listener.process(&mut self.iface, ip_repr, tcp_repr);

                if let Some(tcp_conn) = new_tcp_conn {
                    self.actions.push(SocketTableAction::AddTcpConn(tcp_conn));
                }

                match processed {
                    TcpProcessResult::NotProcessed => {}
                    TcpProcessResult::Processed => return None,
                    TcpProcessResult::ProcessedWithReply(ip_repr, tcp_repr) => {
                        return Some((ip_repr, tcp_repr));
                    }
                }
            }
        }

        // "In no case does receipt of a segment containing RST give rise to a RST in response."
        // See <https://datatracker.ietf.org/doc/html/rfc9293#section-4-1.64>.
        if tcp_repr.control == TcpControl::Rst {
            return None;
        }

        Some(smoltcp::socket::tcp::Socket::rst_reply(ip_repr, tcp_repr))
    }

    fn parse_and_process_udp<'pkt>(
        &mut self,
        ip_repr: &IpRepr,
        ip_payload: &'pkt [u8],
        checksum_caps: &ChecksumCapabilities,
    ) -> Option<Packet<'pkt>> {
        // Parse the UDP header. Ignore the packet if the header is ill-formed.
        let udp_pkt = UdpPacket::new_checked(ip_payload).ok()?;
        let udp_repr = UdpRepr::parse(
            &udp_pkt,
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            checksum_caps,
        )
        .ok()?;

        if !self.process_udp(ip_repr, &udp_repr, udp_pkt.payload()) {
            return self.generate_icmp_unreachable(
                ip_repr,
                ip_payload,
                Icmpv4DstUnreachable::PortUnreachable,
            );
        }

        None
    }

    fn process_udp(&mut self, ip_repr: &IpRepr, udp_repr: &UdpRepr, udp_payload: &[u8]) -> bool {
        let mut processed = false;

        for socket in self.sockets.udp_socket_iter() {
            if !socket.can_process(udp_repr.dst_port) {
                continue;
            }

            processed |= socket.process(self.iface.context_mut(), ip_repr, udp_repr, udp_payload);
            if processed && ip_repr.dst_addr().is_unicast() {
                break;
            }
        }

        processed
    }

    fn parse_and_process_icmpv4<'pkt>(
        &self,
        ip_repr: &IpRepr,
        ip_payload: &'pkt [u8],
        checksum_caps: &ChecksumCapabilities,
    ) -> Option<Packet<'pkt>> {
        let icmp_packet = Icmpv4Packet::new_checked(ip_payload).ok()?;
        let icmp_repr = Icmpv4Repr::parse(&icmp_packet, checksum_caps).ok()?;

        // 最小 Echo responder 支撑 loopback ping，不扩大到完整 ICMP 控制面。
        match icmp_repr {
            Icmpv4Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } if ip_repr.src_addr().is_unicast() && ip_repr.dst_addr().is_unicast() => {
                let icmp_reply = Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                };
                Some(Packet::new_ipv4(
                    Ipv4Repr {
                        src_addr: self
                            .iface
                            .context()
                            .ipv4_addr()
                            .unwrap_or(Ipv4Address::UNSPECIFIED),
                        dst_addr: match ip_repr.src_addr() {
                            IpAddress::Ipv4(src_addr) => src_addr,
                        },
                        next_header: IpProtocol::Icmp,
                        payload_len: icmp_reply.buffer_len(),
                        hop_limit: 64,
                    },
                    IpPayload::Icmpv4(icmp_reply),
                ))
            }
            _ => None,
        }
    }

    fn generate_icmp_unreachable<'pkt>(
        &self,
        ip_repr: &IpRepr,
        ip_payload: &'pkt [u8],
        reason: Icmpv4DstUnreachable,
    ) -> Option<Packet<'pkt>> {
        if !ip_repr.src_addr().is_unicast() || !ip_repr.dst_addr().is_unicast() {
            return None;
        }

        let IpRepr::Ipv4(ipv4_repr) = ip_repr;

        let reply_len = icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU, IPV4_HEADER_LEN);
        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason,
            header: *ipv4_repr,
            data: &ip_payload[..reply_len],
        };

        Some(Packet::new_ipv4(
            Ipv4Repr {
                src_addr: self
                    .iface
                    .context()
                    .ipv4_addr()
                    .unwrap_or(Ipv4Address::UNSPECIFIED),
                dst_addr: ipv4_repr.src_addr,
                next_header: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            },
            IpPayload::Icmpv4(icmp_repr),
        ))
    }

    /// Returns whether the destination address is the unicast address of a local interface.
    ///
    /// Note: "local" means that the IP address belongs to the local interface, not to be confused
    /// with the localhost IP (127.0.0.1).
    fn is_unicast_local(&self, dst_addr: IpAddress) -> bool {
        match dst_addr {
            IpAddress::Ipv4(dst_addr) => self
                .iface
                .context()
                .ipv4_addr()
                .is_some_and(|addr| addr == dst_addr),
        }
    }
}

impl<E: Ext> PollContext<'_, E> {
    pub(super) fn poll_egress<D, Q, R>(
        &mut self,
        device: &mut D,
        dispatch_phy: &mut Q,
        dispatch_raw_phy: &mut R,
    )
    where
        D: Device + ?Sized,
        Q: FnMut(&Packet, &mut Context, D::TxToken<'_>),
        R: FnMut(&RawIpv4TxPacket, &mut Context, D::TxToken<'_>),
    {
        while let Some(tx_token) = device.transmit(self.iface.context().now()) {
            if !self.dispatch_ipv4(tx_token, dispatch_phy, dispatch_raw_phy) {
                break;
            }
        }
    }

    fn dispatch_ipv4<T, Q, R>(
        &mut self,
        tx_token: T,
        dispatch_phy: &mut Q,
        dispatch_raw_phy: &mut R,
    ) -> bool
    where
        T: TxToken,
        Q: FnMut(&Packet, &mut Context, T),
        R: FnMut(&RawIpv4TxPacket, &mut Context, T),
    {
        let (did_something_tcp, tx_token) = self.dispatch_tcp(tx_token, dispatch_phy);

        let Some(tx_token) = tx_token else {
            return did_something_tcp;
        };

        let (did_something_udp, tx_token) = self.dispatch_udp(tx_token, dispatch_phy);

        let Some(tx_token) = tx_token else {
            return did_something_tcp || did_something_udp;
        };

        let (did_something_raw, _tx_token) =
            self.dispatch_raw_ip(tx_token, dispatch_raw_phy);

        did_something_tcp || did_something_udp || did_something_raw
    }

    fn dispatch_tcp<T, Q>(&mut self, tx_token: T, dispatch_phy: &mut Q) -> (bool, Option<T>)
    where
        T: TxToken,
        Q: FnMut(&Packet, &mut Context, T),
    {
        let mut tx_token = Some(tx_token);
        let mut did_something = false;

        loop {
            let Some(socket) = self.iface.pop_pending_tcp() else {
                break;
            };

            // We set `did_something` even if no packets are actually generated. This is because a
            // timer can expire, but no packets are actually generated.
            did_something = true;

            let mut deferred = None;

            let (reply, became_dead) =
                TcpConnectionBg::dispatch(&socket, &mut self.iface, |iface, ip_repr, tcp_repr| {
                    let mut this = PollContext::new(
                        iface,
                        self.sockets,
                        self.actions,
                        self.ingress_ifindex,
                    );

                    if !this.accept_tcp_at(HookPoint::LocalOut, ip_repr, tcp_repr) {
                        return None;
                    }

                    if !this.is_unicast_local(ip_repr.dst_addr()) {
                        let (ip_repr, tcp_repr) =
                            this.rewrite_tcp_postrouting(ip_repr.clone(), *tcp_repr);
                        this.dispatch_outgoing_packet(
                            &Packet::new(ip_repr, IpPayload::Tcp(tcp_repr)),
                            dispatch_phy,
                            tx_token.take().unwrap(),
                        );
                        return None;
                    }

                    if !socket.can_process(tcp_repr.dst_port) {
                        return this.process_tcp(ip_repr, tcp_repr);
                    }

                    // We cannot call `process_tcp` now because it may cause deadlocks. We will copy
                    // the packet and call `process_tcp` after releasing the socket lock.
                    deferred = Some((ip_repr.clone(), {
                        let mut data = vec![0; tcp_repr.buffer_len()];
                        tcp_repr.emit(
                            &mut TcpPacket::new_unchecked(data.as_mut_slice()),
                            &ip_repr.src_addr(),
                            &ip_repr.dst_addr(),
                            &ChecksumCapabilities::ignored(),
                        );
                        data
                    }));

                    None
                });

            if *became_dead {
                self.actions
                    .push(SocketTableAction::DelTcpConn(*socket.connection_key()));
            }

            match (deferred, reply) {
                (None, None) => (),
                (Some((ip_repr, ip_payload)), None) => {
                    if let Some(reply) = self.parse_and_process_tcp(
                        &ip_repr,
                        &ip_payload,
                        &ChecksumCapabilities::ignored(),
                    ) {
                        self.dispatch_outgoing_packet(
                            &reply,
                            dispatch_phy,
                            tx_token.take().unwrap(),
                        );
                    }
                }
                (None, Some((ip_repr, tcp_repr))) if !self.is_unicast_local(ip_repr.dst_addr()) => {
                    if !self.accept_tcp_at(HookPoint::LocalOut, &ip_repr, &tcp_repr) {
                        continue;
                    }
                    let (ip_repr, tcp_repr) = self.rewrite_tcp_postrouting(ip_repr, tcp_repr);
                    self.dispatch_outgoing_packet(
                        &Packet::new(ip_repr, IpPayload::Tcp(tcp_repr)),
                        dispatch_phy,
                        tx_token.take().unwrap(),
                    );
                }
                (None, Some((ip_repr, tcp_repr))) => {
                    if let Some((new_ip_repr, new_tcp_repr)) =
                        self.process_tcp_until_outgoing(&ip_repr, &tcp_repr)
                    {
                        if !self.accept_tcp_at(HookPoint::LocalOut, &new_ip_repr, &new_tcp_repr) {
                            continue;
                        }
                        let (new_ip_repr, new_tcp_repr) =
                            self.rewrite_tcp_postrouting(new_ip_repr, new_tcp_repr);
                        self.dispatch_outgoing_packet(
                            &Packet::new(new_ip_repr, IpPayload::Tcp(new_tcp_repr)),
                            dispatch_phy,
                            tx_token.take().unwrap(),
                        );
                    }
                }
                (Some(_), Some(_)) => unreachable!(),
            }

            if tx_token.is_none() {
                break;
            }
        }

        (did_something, tx_token)
    }

    fn dispatch_udp<T, Q>(&mut self, tx_token: T, dispatch_phy: &mut Q) -> (bool, Option<T>)
    where
        T: TxToken,
        Q: FnMut(&Packet, &mut Context, T),
    {
        let mut tx_token = Some(tx_token);
        let mut did_something = false;

        let mut actions = Vec::new();

        for socket in self.sockets.udp_socket_iter() {
            if !socket.need_dispatch() {
                continue;
            }

            // We set `did_something` even if no packets are actually generated. This is because a
            // timer can expire, but no packets are actually generated.
            did_something = true;

            let mut deferred = None;

            let (cx, pending) = self.iface.inner_mut();
            socket.dispatch(cx, |cx, ip_repr, udp_repr, udp_payload| {
                let iface = PollableIfaceMut::new(cx, pending);
                let mut this = PollContext::new(
                    iface,
                    self.sockets,
                    &mut actions,
                    self.ingress_ifindex,
                );

                if !this.accept_udp_at(HookPoint::LocalOut, ip_repr, udp_repr) {
                    return;
                }

                if ip_repr.dst_addr().is_broadcast() || !this.is_unicast_local(ip_repr.dst_addr()) {
                    let (ip_repr, udp_repr) =
                        this.rewrite_udp_postrouting(ip_repr.clone(), *udp_repr);
                    this.dispatch_outgoing_packet(
                        &Packet::new(ip_repr.clone(), IpPayload::Udp(udp_repr, udp_payload)),
                        dispatch_phy,
                        tx_token.take().unwrap(),
                    );
                    if !ip_repr.dst_addr().is_broadcast() {
                        return;
                    }
                }

                if !socket.can_process(udp_repr.dst_port) {
                    if !this.process_udp(ip_repr, udp_repr, udp_payload) {
                        let mut ip_payload = vec![0; udp_repr.header_len() + udp_payload.len()];
                        udp_repr.emit(
                            &mut UdpPacket::new_unchecked(&mut ip_payload),
                            &ip_repr.src_addr(),
                            &ip_repr.dst_addr(),
                            udp_payload.len(),
                            |payload| payload.copy_from_slice(udp_payload),
                            &ChecksumCapabilities::ignored(),
                        );

                        if let Some(reply) = this.generate_icmp_unreachable(
                            ip_repr,
                            &ip_payload,
                            Icmpv4DstUnreachable::PortUnreachable,
                        ) {
                            this.process_locally_generated_raw_ipv4(&reply);
                        }
                    }
                    return;
                }

                // We cannot call `process_udp` now because it may cause deadlocks. We will copy
                // the packet and call `process_udp` after releasing the socket lock.
                deferred = Some((ip_repr.clone(), {
                    let mut data = vec![0; udp_repr.header_len() + udp_payload.len()];
                    udp_repr.emit(
                        &mut UdpPacket::new_unchecked(&mut data),
                        &ip_repr.src_addr(),
                        &ip_repr.dst_addr(),
                        udp_payload.len(),
                        |payload| payload.copy_from_slice(udp_payload),
                        &ChecksumCapabilities::ignored(),
                    );
                    data
                }));
            });

            if let Some((ip_repr, ip_payload)) = deferred
                && let Some(reply) = self.parse_and_process_udp(
                    &ip_repr,
                    &ip_payload,
                    &ChecksumCapabilities::ignored(),
                )
            {
                self.dispatch_outgoing_packet(&reply, dispatch_phy, tx_token.take().unwrap());
            }

            if tx_token.is_none() {
                break;
            }
        }

        // `actions` should be empty,
        // because we are dealing with UDP sockets,
        // and the `actions` contains only TCP actions.
        debug_assert!(actions.is_empty());

        (did_something, tx_token)
    }

    fn dispatch_raw_ip<T, R>(
        &mut self,
        tx_token: T,
        dispatch_raw_phy: &mut R,
    ) -> (bool, Option<T>)
    where
        T: TxToken,
        R: FnMut(&RawIpv4TxPacket, &mut Context, T),
    {
        let mut tx_token = Some(tx_token);

        for socket in self.sockets.raw_ip_socket_iter() {
            let Some(mut tx_packet) = socket.pop_tx_packet() else {
                continue;
            };

            let destination = tx_packet.destination();
            let is_local = self.is_unicast_local(IpAddress::Ipv4(destination));
            if tx_packet.protocol() != IpProtocol::Icmp {
                // Non-ICMP raw sockets carry an opaque protocol payload.  The
                // `Raw` payload variant deliberately avoids TCP/UDP checksum
                // and header parsing so experimental protocols and packet
                // injection tools can use the normal IPv4 output path.
                let ipv4_repr = tx_packet.ipv4_repr();
                if !self.accept_ipv4_at(HookPoint::LocalOut, &ipv4_repr) {
                    return (true, tx_token);
                }

                if is_local {
                    self.process_locally_generated_raw_ipv4_tx(&tx_packet);
                } else {
                    if !self.accept_ipv4_at(HookPoint::PostRouting, &ipv4_repr) {
                        return (true, tx_token);
                    }
                    dispatch_raw_phy(
                        &tx_packet,
                        self.iface.context_mut(),
                        tx_token.take().unwrap(),
                    );
                }
                return (true, tx_token);
            }

            let IpProtocol::Icmp = tx_packet.protocol() else {
                continue;
            };

            let icmp_packet = match Icmpv4Packet::new_checked(tx_packet.payload()) {
                Ok(icmp_packet) => icmp_packet,
                Err(_) => continue,
            };
            let icmp_repr =
                match Icmpv4Repr::parse(&icmp_packet, &self.iface.context().checksum_caps()) {
                    Ok(icmp_repr) => icmp_repr,
                    Err(_) => continue,
                };
            let is_local = self.is_unicast_local(IpAddress::Ipv4(tx_packet.destination()));
            let mut ipv4_repr = tx_packet.ipv4_repr();
            ipv4_repr.payload_len = icmp_repr.buffer_len();
            if !is_local {
                ipv4_repr = self.rewrite_icmp_postrouting(ipv4_repr);
            }
            let packet = Packet::new_ipv4(ipv4_repr, IpPayload::Icmpv4(icmp_repr));

            if !self.accept_icmpv4_at(HookPoint::LocalOut, &packet.ip_repr(), &icmp_repr) {
                return (true, tx_token);
            }

            // 发往本机地址的 raw ICMP 请求直接回灌协议路径，用于 loopback ping。
            if is_local {
                if let Some(reply) = self.parse_and_process_icmpv4(
                    &packet.ip_repr(),
                    tx_packet.payload(),
                    &self.iface.context().checksum_caps(),
                ) {
                    self.process_locally_generated_raw_ipv4(&reply);
                }
            } else {
                if !self.accept_packet_at(HookPoint::PostRouting, &packet) {
                    return (true, tx_token);
                }

                tx_packet.set_endpoints(ipv4_repr.src_addr, ipv4_repr.dst_addr);
                dispatch_raw_phy(
                    &tx_packet,
                    self.iface.context_mut(),
                    tx_token.take().unwrap(),
                );
            }

            return (true, tx_token);
        }

        (false, tx_token)
    }
}
