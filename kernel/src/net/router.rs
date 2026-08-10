// SPDX-License-Identifier: MPL-2.0

//! Stage 2 IPv4 forwarding policy.
//!
//! Routes are currently the directly connected IPv4 prefixes of registered
//! interfaces.  Static routes, a userspace control surface, ICMP-specific
//! errors, conntrack, and NAT are deliberately later stages.

use core::sync::atomic::{AtomicBool, Ordering};
use alloc::sync::Arc;

use aster_bigtcp::{
    forwarding::{ForwardedIpv4Packet, ForwardedIpv6Packet, ForwardingResult},
    iface::ScheduleNextPoll,
    wire::{Ipv4Address, Ipv6Address},
};
use ostd::timer::Jiffies;

use super::iface::{Iface, iter_all_ifaces};
use crate::prelude::println;

static IPV4_FORWARDING_ENABLED: AtomicBool = AtomicBool::new(false);
static IPV6_FORWARDING_ENABLED: AtomicBool = AtomicBool::new(false);
static STAGE11_IPV6_FORWARD_DROP_TEST: AtomicBool = AtomicBool::new(false);
static STAGE12_IPV6_SNAT_TEST: AtomicBool = AtomicBool::new(false);
static STAGE12_IPV6_DNAT_TEST: AtomicBool = AtomicBool::new(false);
static STAGE3_ICMP_MASQUERADE_TEST: AtomicBool = AtomicBool::new(false);
static STAGE3_ICMP_DNAT_TEST: AtomicBool = AtomicBool::new(false);
static STAGE3_ICMP_FORWARD_DROP_TEST: AtomicBool = AtomicBool::new(false);
static STAGE4_TCP_MASQUERADE_TEST: AtomicBool = AtomicBool::new(false);
static STAGE4_UDP_MASQUERADE_TEST: AtomicBool = AtomicBool::new(false);
static STAGE4_TCP_DNAT_TEST: AtomicBool = AtomicBool::new(false);
static STAGE6_TCP_CONNTRACK_POLICY_TEST: AtomicBool = AtomicBool::new(false);

aster_cmdline::define_flag_param!("netfilter.ipv4_forward", IPV4_FORWARDING_ENABLED);
aster_cmdline::define_flag_param!("netfilter.ipv6_forward", IPV6_FORWARDING_ENABLED);
aster_cmdline::define_flag_param!(
    "netfilter.stage11_ipv6_forward_drop",
    STAGE11_IPV6_FORWARD_DROP_TEST
);
aster_cmdline::define_flag_param!("netfilter.stage12_ipv6_snat", STAGE12_IPV6_SNAT_TEST);
aster_cmdline::define_flag_param!("netfilter.stage12_ipv6_dnat", STAGE12_IPV6_DNAT_TEST);
aster_cmdline::define_flag_param!(
    "netfilter.stage3_icmp_masquerade",
    STAGE3_ICMP_MASQUERADE_TEST
);
aster_cmdline::define_flag_param!("netfilter.stage3_icmp_dnat", STAGE3_ICMP_DNAT_TEST);
aster_cmdline::define_flag_param!(
    "netfilter.stage3_icmp_forward_drop",
    STAGE3_ICMP_FORWARD_DROP_TEST
);
aster_cmdline::define_flag_param!(
    "netfilter.stage4_tcp_masquerade",
    STAGE4_TCP_MASQUERADE_TEST
);
aster_cmdline::define_flag_param!(
    "netfilter.stage4_udp_masquerade",
    STAGE4_UDP_MASQUERADE_TEST
);
aster_cmdline::define_flag_param!("netfilter.stage4_tcp_dnat", STAGE4_TCP_DNAT_TEST);
aster_cmdline::define_flag_param!(
    "netfilter.stage6_tcp_conntrack_policy",
    STAGE6_TCP_CONNTRACK_POLICY_TEST
);

/// Emits an explicit boot-time marker for the Stage 2 forwarding pipeline.
pub fn init() {
    if IPV4_FORWARDING_ENABLED.load(Ordering::Relaxed) {
        println!("netfilter-stage2b: ipv4 forwarding pipeline enabled");
    }
    if IPV6_FORWARDING_ENABLED.load(Ordering::Relaxed) {
        println!("netfilter-stage10d: ipv6 forwarding pipeline enabled");
    }

    if STAGE11_IPV6_FORWARD_DROP_TEST.load(Ordering::Relaxed) {
        let installed = aster_bigtcp::netfilter::append_ipv6_filter_rule(
            aster_bigtcp::netfilter::HookPoint::Forward,
            aster_bigtcp::netfilter::Ipv6RuleProtocol::Icmpv6,
            Some(Ipv6Address::new(0xfd00, 0, 0, 2, 0, 0, 0, 2)),
            Some(Ipv6Address::new(0xfd00, 0, 0, 3, 0, 0, 0, 2)),
            Some(128),
            aster_bigtcp::netfilter::Ipv6RuleTarget::Drop,
        );
        if installed {
            println!("netfilter-stage11: IPv6 ICMPv6 FORWARD DROP acceptance rule installed");
        }
    }

    if STAGE12_IPV6_SNAT_TEST.load(Ordering::Relaxed) {
        let installed = aster_bigtcp::netfilter::append_ipv6_nat_rule(
            aster_bigtcp::netfilter::Ipv6NatRuleChain::PostRouting,
            aster_bigtcp::netfilter::Ipv6RuleProtocol::Any,
            Some(Ipv6Address::new(0xfd00, 0, 0, 2, 0, 0, 0, 2)),
            Some(Ipv6Address::new(0xfd00, 0, 0, 3, 0, 0, 0, 2)),
            None,
            None,
            aster_bigtcp::netfilter::Ipv6NatRuleTarget::Masquerade,
            None,
        );
        if installed {
            println!("netfilter-stage12: IPv6 POSTROUTING MASQUERADE rule installed");
        }
    }

    if STAGE12_IPV6_DNAT_TEST.load(Ordering::Relaxed) {
        let installed = aster_bigtcp::netfilter::append_ipv6_nat_rule(
            aster_bigtcp::netfilter::Ipv6NatRuleChain::PreRouting,
            aster_bigtcp::netfilter::Ipv6RuleProtocol::Any,
            Some(Ipv6Address::new(0xfd00, 0, 0, 2, 0, 0, 0, 2)),
            // IPv6 text is hexadecimal: the virtual service `::15` ends in
            // 0x15, not decimal 15 (`::f`).
            Some(Ipv6Address::new(0xfd00, 0, 0, 3, 0, 0, 0, 0x15)),
            None,
            None,
            aster_bigtcp::netfilter::Ipv6NatRuleTarget::Dnat,
            Some(Ipv6Address::new(0xfd00, 0, 0, 3, 0, 0, 0, 2)),
        );
        if installed {
            println!("netfilter-stage12: IPv6 PREROUTING DNAT rule installed");
        }
    }

    // The TAP acceptance topology cannot run an interactive userspace command
    // in the guest. Install the same in-kernel rule that its iptables parser
    // would create, solely when this explicit test flag is present.
    if STAGE3_ICMP_MASQUERADE_TEST.load(Ordering::Relaxed) {
        let installed = aster_bigtcp::netfilter::append_nat_rule(
            aster_bigtcp::netfilter::NatRuleChain::PostRouting,
            Some(aster_bigtcp::netfilter::OutputRuleProtocol::Icmp),
            Some(Ipv4Address::new(10, 0, 2, 2)),
            Some(Ipv4Address::new(10, 0, 3, 2)),
            None,
            None,
            aster_bigtcp::netfilter::NatRuleTarget::Masquerade,
            None,
            None,
        );
        if installed {
            println!("netfilter-stage3: ICMP MASQUERADE acceptance rule installed");
        }
    }

    if STAGE3_ICMP_DNAT_TEST.load(Ordering::Relaxed) {
        let installed = aster_bigtcp::netfilter::append_nat_rule(
            aster_bigtcp::netfilter::NatRuleChain::PreRouting,
            Some(aster_bigtcp::netfilter::OutputRuleProtocol::Icmp),
            Some(Ipv4Address::new(10, 0, 2, 2)),
            Some(Ipv4Address::new(10, 0, 2, 15)),
            None,
            None,
            aster_bigtcp::netfilter::NatRuleTarget::Dnat,
            Some(Ipv4Address::new(10, 0, 3, 2)),
            None,
        );
        if installed {
            println!("netfilter-stage3: ICMP DNAT acceptance rule installed");
        }
    }

    if STAGE3_ICMP_FORWARD_DROP_TEST.load(Ordering::Relaxed) {
        let installed = aster_bigtcp::netfilter::append_filter_icmp_echo_rule(
            aster_bigtcp::netfilter::HookPoint::Forward,
            None,
            Some(Ipv4Address::new(10, 0, 2, 2)),
            Some(Ipv4Address::new(10, 0, 3, 2)),
            aster_bigtcp::netfilter::OutputRuleTarget::Drop,
        );
        if installed {
            println!("netfilter-stage3: ICMP FORWARD DROP acceptance rule installed");
        }
    }

    // Stage 4 uses explicit boot flags because the TAP acceptance setup does
    // not yet have an interactive guest-side rule-management ABI. These are
    // intentionally ordinary TCP/UDP NAT rules, so the same table API will be
    // used by the later iptables-compatible control plane.
    if STAGE4_TCP_MASQUERADE_TEST.load(Ordering::Relaxed) {
        let installed = aster_bigtcp::netfilter::append_nat_rule(
            aster_bigtcp::netfilter::NatRuleChain::PostRouting,
            Some(aster_bigtcp::netfilter::OutputRuleProtocol::Tcp),
            Some(Ipv4Address::new(10, 0, 2, 2)),
            Some(Ipv4Address::new(10, 0, 3, 2)),
            None,
            Some(9000),
            aster_bigtcp::netfilter::NatRuleTarget::Masquerade,
            None,
            None,
        );
        if installed {
            println!("netfilter-stage4: TCP MASQUERADE acceptance rule installed");
        }
    }

    if STAGE4_UDP_MASQUERADE_TEST.load(Ordering::Relaxed) {
        let installed = aster_bigtcp::netfilter::append_nat_rule(
            aster_bigtcp::netfilter::NatRuleChain::PostRouting,
            Some(aster_bigtcp::netfilter::OutputRuleProtocol::Udp),
            Some(Ipv4Address::new(10, 0, 2, 2)),
            Some(Ipv4Address::new(10, 0, 3, 2)),
            None,
            Some(9001),
            aster_bigtcp::netfilter::NatRuleTarget::Masquerade,
            None,
            None,
        );
        if installed {
            println!("netfilter-stage4: UDP MASQUERADE acceptance rule installed");
        }
    }

    if STAGE4_TCP_DNAT_TEST.load(Ordering::Relaxed) {
        let installed = aster_bigtcp::netfilter::append_nat_rule(
            aster_bigtcp::netfilter::NatRuleChain::PreRouting,
            Some(aster_bigtcp::netfilter::OutputRuleProtocol::Tcp),
            Some(Ipv4Address::new(10, 0, 2, 2)),
            Some(Ipv4Address::new(10, 0, 2, 15)),
            None,
            Some(9002),
            aster_bigtcp::netfilter::NatRuleTarget::Dnat,
            Some(Ipv4Address::new(10, 0, 3, 2)),
            Some(9002),
        );
        if installed {
            println!("netfilter-stage4: TCP DNAT acceptance rule installed");
        }
    }

    if STAGE6_TCP_CONNTRACK_POLICY_TEST.load(Ordering::Relaxed) {
        // The policy is intentionally DROP: a successful bidirectional TCP
        // exchange proves that the outbound SYN matched NEW and the reply
        // tuple was promoted to ESTABLISHED before FORWARD evaluation.
        aster_bigtcp::netfilter::set_filter_chain_policy(
            aster_bigtcp::netfilter::HookPoint::Forward,
            aster_bigtcp::netfilter::OutputRuleTarget::Drop,
        );
        let new_rule = aster_bigtcp::netfilter::append_filter_transport_rule(
            aster_bigtcp::netfilter::HookPoint::Forward,
            aster_bigtcp::netfilter::OutputRuleProtocol::Tcp,
            Some(Ipv4Address::new(10, 0, 2, 2)),
            Some(Ipv4Address::new(10, 0, 3, 2)),
            None,
            Some(9000),
            Some(aster_bigtcp::netfilter::ConntrackState::New),
            aster_bigtcp::netfilter::OutputRuleTarget::Accept,
        );
        let established_rule = aster_bigtcp::netfilter::append_filter_transport_rule(
            aster_bigtcp::netfilter::HookPoint::Forward,
            aster_bigtcp::netfilter::OutputRuleProtocol::Tcp,
            None,
            None,
            None,
            None,
            Some(aster_bigtcp::netfilter::ConntrackState::Established),
            aster_bigtcp::netfilter::OutputRuleTarget::Accept,
        );
        let nat_rule = aster_bigtcp::netfilter::append_nat_rule(
            aster_bigtcp::netfilter::NatRuleChain::PostRouting,
            Some(aster_bigtcp::netfilter::OutputRuleProtocol::Tcp),
            Some(Ipv4Address::new(10, 0, 2, 2)),
            Some(Ipv4Address::new(10, 0, 3, 2)),
            None,
            Some(9000),
            aster_bigtcp::netfilter::NatRuleTarget::Masquerade,
            None,
            None,
        );
        if new_rule && established_rule && nat_rule {
            println!("netfilter-stage6: TCP NEW/ESTABLISHED FORWARD policy installed");
        }
    }
}

/// Selects a directly connected egress route and queues the packet.
pub fn forward_ipv4_packet(
    ingress_ifindex: u32,
    mut packet: ForwardedIpv4Packet,
) -> ForwardingResult {
    if !IPV4_FORWARDING_ENABLED.load(Ordering::Relaxed) {
        return ForwardingResult::Disabled;
    }

    if packet.ip_repr.hop_limit <= 1 {
        return ForwardingResult::HopLimitExceeded;
    }

    let destination = packet.ip_repr.dst_addr;
    let egress = lookup_ipv4_iface(destination, Some(ingress_ifindex));

    let Some(egress) = egress else {
        return ForwardingResult::NoRoute;
    };

    // Ipv4Repr is re-emitted at egress, which computes a fresh header checksum.
    packet.ip_repr.hop_limit -= 1;

    if !egress.enqueue_forwarded_ipv4(packet) {
        return ForwardingResult::QueueFull;
    }

    // Do not synchronously poll the egress interface while the ingress poll
    // still holds its interface lock. An immediate reply can otherwise route
    // back through the ingress interface and spin forever on that same lock.
    let now_ms = Jiffies::elapsed().as_duration().as_millis() as u64;
    egress.sched_poll().schedule_next_poll(Some(now_ms));
    ForwardingResult::Queued
}

/// Selects a directly connected IPv6 egress route and queues the packet.
pub fn forward_ipv6_packet(
    ingress_ifindex: u32,
    mut packet: ForwardedIpv6Packet,
) -> ForwardingResult {
    if !IPV6_FORWARDING_ENABLED.load(Ordering::Relaxed) {
        return ForwardingResult::Disabled;
    }

    if !packet.decrement_hop_limit() {
        return ForwardingResult::HopLimitExceeded;
    }

    let Some(egress) = lookup_ipv6_iface(packet.dst_addr, Some(ingress_ifindex)) else {
        return ForwardingResult::NoRoute;
    };

    // POSTROUTING is evaluated only after the egress interface is known so a
    // MASQUERADE rule can use that interface's IPv6 address.  The NAT module
    // also records the mapping used by the reverse PREROUTING path.
    aster_bigtcp::netfilter::apply_ipv6_nat_postrouting(
        &mut packet,
        egress.ipv6_addr(),
    );

    if !egress.enqueue_forwarded_ipv6(packet) {
        return ForwardingResult::QueueFull;
    }

    // As in the IPv4 path, let the background poller run after the ingress
    // interface lock has been released instead of nesting interface polls.
    let now_ms = Jiffies::elapsed().as_duration().as_millis() as u64;
    egress.sched_poll().schedule_next_poll(Some(now_ms));
    ForwardingResult::Queued
}

/// Looks up the egress interface for an IPv4 destination.
///
/// Connected prefixes win by longest-prefix match.  If no connected route
/// matches, an interface with a configured gateway supplies the default route.
/// The optional exclusion is used by forwarding so a packet cannot be queued
/// back onto the interface it arrived on.
pub(crate) fn lookup_ipv4_iface(
    destination: Ipv4Address,
    exclude_ifindex: Option<u32>,
) -> Option<Arc<Iface>> {
    let mut best_connected: Option<(u8, Arc<Iface>)> = None;

    for iface in iter_all_ifaces() {
        if exclude_ifindex.is_some_and(|index| iface.index() == index) {
            continue;
        }

        let Some(address) = iface.ipv4_addr() else {
            continue;
        };
        let prefix_len = iface.prefix_len().unwrap_or(0).min(32);
        if route_matches(destination, address, prefix_len)
            && best_connected
                .as_ref()
                .map_or(true, |(best_prefix, _)| prefix_len > *best_prefix)
        {
            best_connected = Some((prefix_len, iface.clone()));
        }
    }

    if let Some((_, iface)) = best_connected {
        return Some(iface);
    }

    iter_all_ifaces()
        .filter(|iface| !exclude_ifindex.is_some_and(|index| iface.index() == index))
        .find(|iface| iface.ipv4_addr().is_some() && iface.ipv4_gateway().is_some())
        .cloned()
}

/// Looks up the egress interface for an IPv6 destination.
pub(crate) fn lookup_ipv6_iface(
    destination: Ipv6Address,
    exclude_ifindex: Option<u32>,
) -> Option<Arc<Iface>> {
    let mut best_connected: Option<(u8, Arc<Iface>)> = None;

    for iface in iter_all_ifaces() {
        if exclude_ifindex.is_some_and(|index| iface.index() == index) {
            continue;
        }

        let Some(address) = iface.ipv6_addr() else {
            continue;
        };
        let prefix_len = iface.ipv6_prefix_len().unwrap_or(0).min(128);
        if route_matches_ipv6(destination, address, prefix_len)
            && best_connected
                .as_ref()
                .map_or(true, |(best_prefix, _)| prefix_len > *best_prefix)
        {
            best_connected = Some((prefix_len, iface.clone()));
        }
    }

    if let Some((_, iface)) = best_connected {
        return Some(iface);
    }

    iter_all_ifaces()
        .filter(|iface| !exclude_ifindex.is_some_and(|index| iface.index() == index))
        .find(|iface| iface.ipv6_addr().is_some() && iface.ipv6_gateway().is_some())
        .cloned()
}

fn route_matches(destination: Ipv4Address, address: Ipv4Address, prefix_len: u8) -> bool {
    let prefix_len = prefix_len.min(32);
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (u32::from_be_bytes(destination.octets()) & mask)
        == (u32::from_be_bytes(address.octets()) & mask)
}

fn route_matches_ipv6(destination: Ipv6Address, address: Ipv6Address, prefix_len: u8) -> bool {
    let prefix_len = prefix_len.min(128) as usize;
    let destination = destination.octets();
    let address = address.octets();
    let full_bytes = prefix_len / 8;
    let remaining_bits = prefix_len % 8;

    if destination[..full_bytes] != address[..full_bytes] {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }

    let mask = 0xffu8 << (8 - remaining_bits);
    destination[full_bytes] & mask == address[full_bytes] & mask
}

#[cfg(test)]
mod tests {
    use super::{route_matches, route_matches_ipv6};
    use aster_bigtcp::wire::{Ipv4Address, Ipv6Address};

    #[test]
    fn route_matching_honors_prefix_length() {
        let network_address = Ipv4Address::new(10, 0, 3, 15);
        assert!(route_matches(
            Ipv4Address::new(10, 0, 3, 2),
            network_address,
            24
        ));
        assert!(!route_matches(
            Ipv4Address::new(10, 0, 2, 2),
            network_address,
            24
        ));
    }

    #[test]
    fn ipv6_route_matching_honors_prefix_length() {
        let network_address = Ipv6Address::new(0xfd00, 0, 0, 3, 0, 0, 0, 15);
        assert!(route_matches_ipv6(
            Ipv6Address::new(0xfd00, 0, 0, 3, 0, 0, 0, 2),
            network_address,
            64
        ));
        assert!(!route_matches_ipv6(
            Ipv6Address::new(0xfd00, 0, 0, 2, 0, 0, 0, 2),
            network_address,
            64
        ));
    }
}
