// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::btree_map::BTreeMap, string::String, sync::Arc, vec, vec::Vec};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::{
    iface::{Config, Context, packet::Packet},
    phy::{Device, DeviceCapabilities, TxToken},
    wire::{
        self, ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
        EthernetRepr, IpAddress, Ipv4Address, Ipv4AddressExt, Ipv4Cidr, Ipv4Packet, Ipv6Address,
        Ipv6Cidr,
    },
};

use crate::{
    device::{NotifyDevice, WithDevice},
    ext::Ext,
    forwarding::{ForwardedIpv4Packet, ForwardedIpv6Packet},
    socket::RawIpv4TxPacket,
    iface::{
        Iface, InterfaceFlags, ScheduleNextPoll,
        common::{IfaceCommon, InterfaceType},
        iface::internal::IfaceInternal,
        time::get_network_timestamp,
    },
};

pub struct EtherIface<D, E: Ext> {
    driver: D,
    common: IfaceCommon<E>,
    ether_addr: EthernetAddress,
    arp_table: SpinLock<BTreeMap<Ipv4Address, EthernetAddress>, BottomHalfDisabled>,
    /// A small, non-expiring IPv6 neighbor cache used by the packet-path
    /// implementation.  NDP advertisements refresh entries; a later stage
    /// will add timers and queue packets while resolution is in progress.
    ndp_table: SpinLock<BTreeMap<Ipv6Address, EthernetAddress>, BottomHalfDisabled>,
}

impl<D: WithDevice, E: Ext> EtherIface<D, E> {
    pub fn new(
        driver: D,
        ether_addr: EthernetAddress,
        ip_cidr: Ipv4Cidr,
        gateway: Ipv4Address,
        ipv6_cidr: Ipv6Cidr,
        ipv6_gateway: Ipv6Address,
        name: String,
        sched_poll: E::ScheduleNextPoll,
        flags: InterfaceFlags,
    ) -> Arc<Self> {
        let interface = driver.with(|device| {
            let config = Config::new(wire::HardwareAddress::Ethernet(ether_addr));
            let now = get_network_timestamp();

            let mut interface = smoltcp::iface::Interface::new(config, device, now);
            interface.update_ip_addrs(|ip_addrs| {
                debug_assert!(ip_addrs.is_empty());
                ip_addrs.push(wire::IpCidr::Ipv4(ip_cidr)).unwrap();
                ip_addrs.push(wire::IpCidr::Ipv6(ipv6_cidr)).unwrap();
            });
            interface
                .routes_mut()
                .add_default_ipv4_route(gateway)
                .unwrap();
            interface
                .routes_mut()
                .add_default_ipv6_route(ipv6_gateway)
                .unwrap();
            interface
        });

        let common = IfaceCommon::new(
            name,
            InterfaceType::ETHER,
            flags,
            Some(gateway),
            Some(ipv6_gateway),
            interface,
            sched_poll,
        );

        Arc::new(Self {
            driver,
            common,
            ether_addr,
            arp_table: SpinLock::new(BTreeMap::new()),
            ndp_table: SpinLock::new(BTreeMap::new()),
        })
    }
}

impl<D, E: Ext> IfaceInternal<E> for EtherIface<D, E> {
    fn common(&self) -> &IfaceCommon<E> {
        &self.common
    }
}

impl<D: WithDevice + 'static, E: Ext> Iface<E> for EtherIface<D, E>
where
    D::Device: NotifyDevice,
{
    fn poll(&self) {
        self.driver.with(|device| {
            let next_poll = self.common.poll(
                &mut *device,
                |data, iface_cx, tx_token| self.process(data, iface_cx, tx_token),
                |pkt, iface_cx, tx_token| self.dispatch(pkt, iface_cx, tx_token),
                |pkt, iface_cx, tx_token| self.dispatch_forwarded(pkt, iface_cx, tx_token),
                |pkt, iface_cx, tx_token| {
                    self.dispatch_forwarded_ipv6(pkt, iface_cx, tx_token)
                },
                |pkt, iface_cx, tx_token| self.dispatch_raw(pkt, iface_cx, tx_token),
            );
            device.notify_poll_end();
            self.common.sched_poll().schedule_next_poll(next_poll);
        });
    }

    fn mtu(&self) -> usize {
        self.driver
            .with(|device| device.capabilities().max_transmission_unit)
    }
}

impl<D, E: Ext> EtherIface<D, E> {
    fn process<'pkt, T: TxToken>(
        &self,
        data: &'pkt [u8],
        iface_cx: &mut Context,
        tx_token: T,
    ) -> Option<(Ipv4Packet<&'pkt [u8]>, T)> {
        // IPv6 is handled before the IPv4-only poll context.  This keeps the
        // existing IPv4/NAT path unchanged while giving Ethernet interfaces a
        // real ICMPv6 + NDP receive path.  The reply consumes the transmit
        // token directly, just like an ARP response does below.
        if let Ok(frame) = EthernetFrame::new_checked(data) {
            if let Ok(repr) = EthernetRepr::parse(&frame) {
                if repr.ethertype == EthernetProtocol::Ipv6 {
                    if !repr.dst_addr.is_broadcast()
                        && !repr.dst_addr.is_multicast()
                        && repr.dst_addr != self.ether_addr
                    {
                        return None;
                    }
                    self.process_ipv6_frame(frame.payload(), &repr, iface_cx, tx_token);
                    return None;
                }
            }
        }

        match self.parse_ip_or_process_arp(data, iface_cx) {
            Ok(pkt) => Some((pkt, tx_token)),
            Err(Some(arp)) => {
                Self::emit_arp(&arp, tx_token);
                None
            }
            Err(None) => None,
        }
    }

    fn parse_ip_or_process_arp<'pkt>(
        &self,
        data: &'pkt [u8],
        iface_cx: &mut Context,
    ) -> Result<Ipv4Packet<&'pkt [u8]>, Option<ArpRepr>> {
        // Parse the Ethernet header. Ignore the packet if the header is ill-formed.
        let frame = EthernetFrame::new_checked(data).map_err(|_| None)?;
        let repr = EthernetRepr::parse(&frame).map_err(|_| None)?;

        // Ignore the Ethernet frame if it is not sent to us.
        if !repr.dst_addr.is_broadcast()
            && !repr.dst_addr.is_multicast()
            && repr.dst_addr != self.ether_addr
        {
            return Err(None);
        }

        // Ignore the Ethernet frame if the protocol is not supported.
        match repr.ethertype {
            EthernetProtocol::Ipv4 => {
                Ok(Ipv4Packet::new_checked(frame.payload()).map_err(|_| None)?)
            }
            EthernetProtocol::Arp => {
                let pkt = ArpPacket::new_checked(frame.payload()).map_err(|_| None)?;
                let arp = ArpRepr::parse(&pkt).map_err(|_| None)?;
                Err(self.process_arp(&arp, iface_cx))
            }
            _ => Err(None),
        }
    }

    /// Processes the fixed-header ICMPv6 messages needed to make an Ethernet
    /// interface usable by ordinary `ping -6` peers.  We intentionally keep
    /// this routine byte-oriented: the vendored smoltcp wire API is used by
    /// the existing IPv4 path, while this boundary must also accept frames
    /// before they can enter that IPv4-only poll context.
    fn process_ipv6_frame<T: TxToken>(
        &self,
        packet: &[u8],
        ether_repr: &EthernetRepr,
        iface_cx: &mut Context,
        tx_token: T,
    ) {
        const IPV6_HEADER_LEN: usize = 40;
        const ICMPV6_PROTO: u8 = 58;
        const ICMPV6_ECHO_REQUEST: u8 = 128;
        const ICMPV6_ECHO_REPLY: u8 = 129;
        const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
        const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;

        if packet.len() < IPV6_HEADER_LEN || packet[0] >> 4 != 6 {
            return;
        }
        let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        if IPV6_HEADER_LEN + payload_len > packet.len() {
            return;
        }

        // PREROUTING owns both configured DNAT and the reverse half of an
        // existing NAT66 connection.  Work on a bounded copy so the
        // Ethernet receive buffer remains immutable while the translated
        // addresses and transport checksum are validated below.
        let mut translated_packet = packet[..IPV6_HEADER_LEN + payload_len].to_vec();
        crate::netfilter::apply_ipv6_nat_prerouting(&mut translated_packet);
        let packet = translated_packet.as_slice();

        let Some(source) = Self::ipv6_from_bytes(&packet[8..24]) else {
            return;
        };
        let Some(destination) = Self::ipv6_from_bytes(&packet[24..40]) else {
            return;
        };

        let is_local = iface_cx
            .ipv6_addr()
            .is_some_and(|local| destination == local);
        let hook_point = if is_local {
            crate::netfilter::HookPoint::LocalIn
        } else {
            crate::netfilter::HookPoint::Forward
        };
        let icmpv6_type = (packet[6] == ICMPV6_PROTO && payload_len != 0)
            .then_some(packet[IPV6_HEADER_LEN]);
        let context = crate::netfilter::Ipv6PacketContext::new(
            hook_point,
            source,
            destination,
            packet[6],
            icmpv6_type,
            payload_len,
        );
        if !crate::netfilter::evaluate_ipv6(context).is_accept() {
            return;
        }

        // A non-local unicast frame is a routed datagram. Keep extension
        // headers and opaque transport payloads intact; IPv6 forwarding only
        // decrements Hop Limit before handing the packet to the platform
        // routing policy.
        if !destination.is_multicast()
            && iface_cx
                .ipv6_addr()
                .map_or(true, |local| destination != local)
        {
            let Some(forwarded) = ForwardedIpv6Packet::new(translated_packet) else {
                return;
            };
            let _ = E::forward_ipv6_packet(self.common.index(), forwarded);
            return;
        }

        if packet[6] != ICMPV6_PROTO || payload_len < 4 {
            return;
        }
        let icmp = &packet[IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_len];

        match icmp[0] {
            ICMPV6_NEIGHBOR_SOLICIT if icmp.len() >= 24 => {
                if let Some(address) = Self::ndp_option_ethernet(icmp, 1) {
                    if source != Ipv6Address::UNSPECIFIED {
                        self.ndp_table.lock().insert(source, address);
                    }
                }

                let Some(local) = iface_cx.ipv6_addr() else {
                    return;
                };
                let Some(target) = Self::ipv6_from_bytes(&icmp[8..24]) else {
                    return;
                };
                if target != local {
                    return;
                }

                let destination = if source == Ipv6Address::UNSPECIFIED {
                    Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
                } else {
                    source
                };
                let destination_ether = if source == Ipv6Address::UNSPECIFIED {
                    EthernetAddress([0x33, 0x33, 0, 0, 0, 1])
                } else {
                    ether_repr.src_addr
                };
                let reply = self.build_neighbor_advertisement(local, destination);
                let ether = EthernetRepr {
                    src_addr: self.ether_addr,
                    dst_addr: destination_ether,
                    ethertype: EthernetProtocol::Ipv6,
                };
                Self::emit_ipv6_frame(&ether, &reply, tx_token);
            }
            ICMPV6_NEIGHBOR_ADVERT if icmp.len() >= 24 => {
                let Some(target) = Self::ipv6_from_bytes(&icmp[8..24]) else {
                    return;
                };
                if let Some(address) = Self::ndp_option_ethernet(icmp, 2) {
                    self.ndp_table.lock().insert(target, address);
                }
            }
            ICMPV6_ECHO_REQUEST => {
                let Some(local) = iface_cx.ipv6_addr() else {
                    return;
                };
                if destination != local {
                    return;
                }
                let reply = Self::build_echo_reply(packet, payload_len);
                let ether = EthernetRepr {
                    src_addr: self.ether_addr,
                    dst_addr: ether_repr.src_addr,
                    ethertype: EthernetProtocol::Ipv6,
                };
                Self::emit_ipv6_frame(&ether, &reply, tx_token);
            }
            ICMPV6_ECHO_REPLY => {
                // Echo replies are consumed by the future IPv6 raw/ICMP
                // socket path.  The NDP cache update above remains useful for
                // subsequent egress packets.
            }
            _ => {}
        }
    }

    fn ipv6_from_bytes(bytes: &[u8]) -> Option<Ipv6Address> {
        if bytes.len() != 16 {
            return None;
        }
        Some(Ipv6Address::new(
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
            u16::from_be_bytes([bytes[6], bytes[7]]),
            u16::from_be_bytes([bytes[8], bytes[9]]),
            u16::from_be_bytes([bytes[10], bytes[11]]),
            u16::from_be_bytes([bytes[12], bytes[13]]),
            u16::from_be_bytes([bytes[14], bytes[15]]),
        ))
    }

    fn ndp_option_ethernet(icmp: &[u8], option_type: u8) -> Option<EthernetAddress> {
        let mut offset = 24;
        while offset + 2 <= icmp.len() {
            let length = (icmp[offset + 1] as usize) * 8;
            if length == 0 || offset + length > icmp.len() {
                break;
            }
            if icmp[offset] == option_type && length >= 8 {
                return Some(EthernetAddress::from_bytes(&icmp[offset + 2..offset + 8]));
            }
            offset += length;
        }
        None
    }

    fn build_echo_reply(packet: &[u8], payload_len: usize) -> Vec<u8> {
        const IPV6_HEADER_LEN: usize = 40;
        let mut reply = Vec::with_capacity(IPV6_HEADER_LEN + payload_len);
        reply.extend_from_slice(&packet[..IPV6_HEADER_LEN + payload_len]);

        let mut source = [0; 16];
        source.copy_from_slice(&reply[8..24]);
        let mut destination = [0; 16];
        destination.copy_from_slice(&reply[24..40]);
        reply[8..24].copy_from_slice(&destination);
        reply[24..40].copy_from_slice(&source);
        reply[7] = 64;
        reply[40] = 129;
        reply[42] = 0;
        reply[43] = 0;
        let checksum = Self::ipv6_checksum(&reply[8..24], &reply[24..40], &reply[40..]);
        reply[42..44].copy_from_slice(&checksum.to_be_bytes());
        reply
    }

    fn ipv6_multicast_ethernet(address: Ipv6Address) -> EthernetAddress {
        let octets = address.octets();
        EthernetAddress([0x33, 0x33, octets[12], octets[13], octets[14], octets[15]])
    }

    fn solicited_node_multicast(target: Ipv6Address) -> Ipv6Address {
        let octets = target.octets();
        Ipv6Address::new(
            0xff02,
            0,
            0,
            0,
            0,
            1,
            0xff00 | u16::from(octets[13]),
            u16::from_be_bytes([octets[14], octets[15]]),
        )
    }

    fn build_neighbor_solicitation(
        &self,
        source: Ipv6Address,
        target: Ipv6Address,
    ) -> Vec<u8> {
        const IPV6_HEADER_LEN: usize = 40;
        const NDP_PAYLOAD_LEN: usize = 32;
        let destination = Self::solicited_node_multicast(target);
        let mut packet = vec![0; IPV6_HEADER_LEN + NDP_PAYLOAD_LEN];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(NDP_PAYLOAD_LEN as u16).to_be_bytes());
        packet[6] = 58;
        packet[7] = 255;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40] = 135;
        packet[48..64].copy_from_slice(&target.octets());
        packet[64] = 1; // Source link-layer address.
        packet[65] = 1; // One 8-byte option unit.
        packet[66..72].copy_from_slice(self.ether_addr.as_bytes());
        let checksum = Self::ipv6_checksum(&packet[8..24], &packet[24..40], &packet[40..]);
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn build_neighbor_advertisement(&self, source: Ipv6Address, destination: Ipv6Address) -> Vec<u8> {
        const IPV6_HEADER_LEN: usize = 40;
        const NDP_PAYLOAD_LEN: usize = 32;
        let mut reply = vec![0; IPV6_HEADER_LEN + NDP_PAYLOAD_LEN];
        reply[0] = 0x60;
        reply[4..6].copy_from_slice(&(NDP_PAYLOAD_LEN as u16).to_be_bytes());
        reply[6] = 58;
        reply[7] = 255;
        reply[8..24].copy_from_slice(&source.octets());
        reply[24..40].copy_from_slice(&destination.octets());

        reply[40] = 136;
        reply[44] = 0x60; // Solicited + Override.
        reply[48..64].copy_from_slice(&source.octets());
        reply[64] = 2; // Target link-layer address.
        reply[65] = 1; // One 8-byte option unit.
        reply[66..72].copy_from_slice(self.ether_addr.as_bytes());
        reply[42] = 0;
        reply[43] = 0;
        let checksum = Self::ipv6_checksum(&reply[8..24], &reply[24..40], &reply[40..]);
        reply[42..44].copy_from_slice(&checksum.to_be_bytes());
        reply
    }

    fn ipv6_checksum(source: &[u8], destination: &[u8], payload: &[u8]) -> u16 {
        fn add(mut sum: u32, bytes: &[u8]) -> u32 {
            let mut chunks = bytes.chunks_exact(2);
            for chunk in &mut chunks {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            }
            if let Some(&byte) = chunks.remainder().first() {
                sum += (byte as u32) << 8;
            }
            sum
        }

        let mut sum = 0;
        sum = add(sum, source);
        sum = add(sum, destination);
        sum += (payload.len() as u32) >> 16;
        sum += (payload.len() as u32) & 0xffff;
        sum += 58;
        sum = add(sum, payload);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn emit_ipv6_frame<T: TxToken>(ether_repr: &EthernetRepr, packet: &[u8], tx_token: T) {
        tx_token.consume(ether_repr.buffer_len() + packet.len(), |buffer| {
            let mut frame = EthernetFrame::new_unchecked(buffer);
            ether_repr.emit(&mut frame);
            frame.payload_mut().copy_from_slice(packet);
        });
    }

    fn process_arp(&self, arp_repr: &ArpRepr, iface_cx: &mut Context) -> Option<ArpRepr> {
        match arp_repr {
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr,
                source_protocol_addr,
                ..
            } => {
                // Ignore the ARP packet if the source addresses are not unicast or not local.
                if !source_hardware_addr.is_unicast()
                    || !iface_cx.in_same_network(&IpAddress::Ipv4(*source_protocol_addr))
                {
                    return None;
                }

                // Insert the mapping between the Ethernet address and the IP address.
                //
                // TODO: Remove the mapping if it expires.
                self.arp_table
                    .lock()
                    .insert(*source_protocol_addr, *source_hardware_addr);

                None
            }
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr,
                source_protocol_addr,
                target_protocol_addr,
                ..
            } => {
                // Ignore the ARP packet if the source addresses are not unicast.
                if !source_hardware_addr.is_unicast() || !source_protocol_addr.x_is_unicast() {
                    return None;
                }

                // Ignore the ARP packet if we do not own the target address.
                if iface_cx
                    .ipv4_addr()
                    .is_none_or(|addr| addr != *target_protocol_addr)
                {
                    return None;
                }

                Some(ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Reply,
                    source_hardware_addr: self.ether_addr,
                    source_protocol_addr: *target_protocol_addr,
                    target_hardware_addr: *source_hardware_addr,
                    target_protocol_addr: *source_protocol_addr,
                })
            }
            _ => None,
        }
    }

    fn dispatch<T: TxToken>(&self, pkt: &Packet, iface_cx: &mut Context, tx_token: T) {
        match self.resolve_ether_or_generate_arp(pkt, iface_cx) {
            Ok(ether) => Self::emit_ip(&ether, pkt, &iface_cx.caps, tx_token),
            Err(Some(arp)) => Self::emit_arp(&arp, tx_token),
            Err(None) => (),
        }
    }

    fn dispatch_forwarded<T: TxToken>(
        &self,
        pkt: &ForwardedIpv4Packet,
        iface_cx: &mut Context,
        tx_token: T,
    ) -> bool {
        let ether = match self.resolve_ether_or_generate_arp_for_addr(
            IpAddress::Ipv4(pkt.ip_repr.dst_addr),
            iface_cx,
        ) {
            Ok(ether) => ether,
            Err(Some(arp)) => {
                Self::emit_arp(&arp, tx_token);
                return false;
            }
            Err(None) => return true,
        };

        Self::emit_forwarded_ip(&ether, pkt, &iface_cx.caps, tx_token);
        true
    }

    fn dispatch_forwarded_ipv6<T: TxToken>(
        &self,
        pkt: &ForwardedIpv6Packet,
        iface_cx: &mut Context,
        tx_token: T,
    ) -> bool {
        let Some(IpAddress::Ipv6(next_hop)) =
            iface_cx.route(&IpAddress::Ipv6(pkt.dst_addr), iface_cx.now())
        else {
            return true;
        };

        let next_hop_ether = if next_hop.is_multicast() {
            Self::ipv6_multicast_ethernet(next_hop)
        } else if let Some(address) = self.ndp_table.lock().get(&next_hop) {
            *address
        } else {
            // A forwarded packet is kept at the head of the queue while the
            // solicitation consumes this transmit token. The Neighbor
            // Advertisement is processed on the next receive poll.
            let Some(source) = iface_cx.ipv6_addr() else {
                return true;
            };
            let destination = Self::solicited_node_multicast(next_hop);
            let ether = EthernetRepr {
                src_addr: self.ether_addr,
                dst_addr: Self::ipv6_multicast_ethernet(destination),
                ethertype: EthernetProtocol::Ipv6,
            };
            let solicitation = self.build_neighbor_solicitation(source, next_hop);
            Self::emit_ipv6_frame(&ether, &solicitation, tx_token);
            return false;
        };

        let ether = EthernetRepr {
            src_addr: self.ether_addr,
            dst_addr: next_hop_ether,
            ethertype: EthernetProtocol::Ipv6,
        };
        Self::emit_forwarded_ipv6(&ether, pkt, tx_token);
        true
    }

    fn dispatch_raw<T: TxToken>(
        &self,
        pkt: &RawIpv4TxPacket,
        iface_cx: &mut Context,
        tx_token: T,
    ) {
        let ether = match self.resolve_ether_or_generate_arp_for_addr(
            IpAddress::Ipv4(pkt.destination()),
            iface_cx,
        ) {
            Ok(ether) => ether,
            Err(Some(arp)) => {
                Self::emit_arp(&arp, tx_token);
                return;
            }
            Err(None) => return,
        };

        Self::emit_raw_ip(&ether, pkt, &iface_cx.caps, tx_token);
    }

    fn resolve_ether_or_generate_arp(
        &self,
        pkt: &Packet,
        iface_cx: &mut Context,
    ) -> Result<EthernetRepr, Option<ArpRepr>> {
        self.resolve_ether_or_generate_arp_for_addr(pkt.ip_repr().dst_addr(), iface_cx)
    }

    fn resolve_ether_or_generate_arp_for_addr(
        &self,
        dst_addr: IpAddress,
        iface_cx: &mut Context,
    ) -> Result<EthernetRepr, Option<ArpRepr>> {
        // Resolve the next-hop IP address.
        let next_hop_ip = match iface_cx.route(&dst_addr, iface_cx.now()) {
            Some(IpAddress::Ipv4(next_hop_ip)) => next_hop_ip,
            Some(IpAddress::Ipv6(next_hop_ip)) => {
                let next_hop_ether = if next_hop_ip.is_multicast() {
                    let octets = next_hop_ip.octets();
                    EthernetAddress([0x33, 0x33, octets[12], octets[13], octets[14], octets[15]])
                } else if let Some(next_hop_ether) = self.ndp_table.lock().get(&next_hop_ip) {
                    *next_hop_ether
                } else {
                    // NDP solicitation/retransmission is emitted by the
                    // receive path in this stage.  Do not send an IPv6 frame
                    // to an unresolved unicast neighbor.
                    return Err(None);
                };

                return Ok(EthernetRepr {
                    src_addr: self.ether_addr,
                    dst_addr: next_hop_ether,
                    ethertype: EthernetProtocol::Ipv6,
                });
            }
            None => return Err(None),
        };

        // Resolve the next-hop Ethernet address.
        let next_hop_ether = if next_hop_ip.is_broadcast() {
            EthernetAddress::BROADCAST
        } else if let Some(next_hop_ether) = self.arp_table.lock().get(&next_hop_ip) {
            *next_hop_ether
        } else {
            // If the next-hop Ethernet address cannot be resolved, ask for it.
            // Forwarded packets are requeued by the caller after the ARP frame
            // consumes this transmit token, so they can be sent after the ARP
            // reply is processed instead of depending on upper-layer retries.
            return Err(Some(ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: self.ether_addr,
                source_protocol_addr: iface_cx.ipv4_addr().unwrap_or(Ipv4Address::UNSPECIFIED),
                target_hardware_addr: EthernetAddress::BROADCAST,
                target_protocol_addr: next_hop_ip,
            }));
        };

        Ok(EthernetRepr {
            src_addr: self.ether_addr,
            dst_addr: next_hop_ether,
            ethertype: EthernetProtocol::Ipv4,
        })
    }

    /// Consumes the token and emits an IP packet.
    fn emit_ip<T: TxToken>(
        ether_repr: &EthernetRepr,
        ip_pkt: &Packet,
        caps: &DeviceCapabilities,
        tx_token: T,
    ) {
        tx_token.consume(
            ether_repr.buffer_len() + ip_pkt.ip_repr().buffer_len(),
            |buffer| {
                let mut frame = EthernetFrame::new_unchecked(buffer);
                ether_repr.emit(&mut frame);

                let ip_repr = ip_pkt.ip_repr();
                ip_repr.emit(frame.payload_mut(), &caps.checksum);
                ip_pkt.emit_payload(
                    &ip_repr,
                    &mut frame.payload_mut()[ip_repr.header_len()..],
                    caps,
                );
            },
        );
    }

    /// Consumes the token and emits a routed packet without reparsing or
    /// mutating its transport payload.
    fn emit_forwarded_ip<T: TxToken>(
        ether_repr: &EthernetRepr,
        packet: &ForwardedIpv4Packet,
        caps: &DeviceCapabilities,
        tx_token: T,
    ) {
        tx_token.consume(
            ether_repr.buffer_len() + packet.buffer_len(),
            |buffer| {
                let mut frame = EthernetFrame::new_unchecked(buffer);
                ether_repr.emit(&mut frame);
                let mut ip_packet = Ipv4Packet::new_unchecked(frame.payload_mut());
                packet.ip_repr.emit(&mut ip_packet, &caps.checksum);
                ip_packet.payload_mut().copy_from_slice(&packet.payload);
            },
        );
    }

    fn emit_forwarded_ipv6<T: TxToken>(
        ether_repr: &EthernetRepr,
        packet: &ForwardedIpv6Packet,
        tx_token: T,
    ) {
        tx_token.consume(ether_repr.buffer_len() + packet.buffer_len(), |buffer| {
            let mut frame = EthernetFrame::new_unchecked(buffer);
            ether_repr.emit(&mut frame);
            frame.payload_mut().copy_from_slice(packet.bytes());
        });
    }

    fn emit_raw_ip<T: TxToken>(
        ether_repr: &EthernetRepr,
        packet: &RawIpv4TxPacket,
        caps: &DeviceCapabilities,
        tx_token: T,
    ) {
        tx_token.consume(ether_repr.buffer_len() + packet.buffer_len(), |buffer| {
            let mut frame = EthernetFrame::new_unchecked(buffer);
            ether_repr.emit(&mut frame);
            packet.emit_ipv4(frame.payload_mut(), &caps.checksum);
        });
    }

    /// Consumes the token and emits an ARP packet.
    fn emit_arp<T: TxToken>(arp_repr: &ArpRepr, tx_token: T) {
        let ether_repr = match arp_repr {
            ArpRepr::EthernetIpv4 {
                source_hardware_addr,
                target_hardware_addr,
                ..
            } => EthernetRepr {
                src_addr: *source_hardware_addr,
                dst_addr: *target_hardware_addr,
                ethertype: EthernetProtocol::Arp,
            },
            _ => return,
        };

        tx_token.consume(ether_repr.buffer_len() + arp_repr.buffer_len(), |buffer| {
            let mut frame = EthernetFrame::new_unchecked(buffer);
            ether_repr.emit(&mut frame);

            let mut pkt = ArpPacket::new_unchecked(frame.payload_mut());
            arp_repr.emit(&mut pkt);
        });
    }
}
