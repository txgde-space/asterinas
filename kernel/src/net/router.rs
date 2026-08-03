// SPDX-License-Identifier: MPL-2.0

//! Stage 2 IPv4 forwarding policy.
//!
//! Routes are currently the directly connected IPv4 prefixes of registered
//! interfaces.  Static routes, a userspace control surface, ICMP-specific
//! errors, conntrack, and NAT are deliberately later stages.

use core::sync::atomic::{AtomicBool, Ordering};
use alloc::sync::Arc;

use aster_bigtcp::{
    forwarding::{ForwardedIpv4Packet, ForwardingResult},
    wire::Ipv4Address,
};

use super::iface::{Iface, iter_all_ifaces};
use crate::prelude::println;

static IPV4_FORWARDING_ENABLED: AtomicBool = AtomicBool::new(false);
static STAGE3_ICMP_MASQUERADE_TEST: AtomicBool = AtomicBool::new(false);
static STAGE3_ICMP_DNAT_TEST: AtomicBool = AtomicBool::new(false);
static STAGE3_ICMP_FORWARD_DROP_TEST: AtomicBool = AtomicBool::new(false);
static STAGE4_TCP_MASQUERADE_TEST: AtomicBool = AtomicBool::new(false);
static STAGE4_UDP_MASQUERADE_TEST: AtomicBool = AtomicBool::new(false);
static STAGE4_TCP_DNAT_TEST: AtomicBool = AtomicBool::new(false);
static STAGE6_TCP_CONNTRACK_POLICY_TEST: AtomicBool = AtomicBool::new(false);

aster_cmdline::define_flag_param!("netfilter.ipv4_forward", IPV4_FORWARDING_ENABLED);
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

    // The queues are per-interface and the ingress interface is excluded above,
    // so this does not recurse into the current device lock.
    egress.poll();
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

#[cfg(test)]
mod tests {
    use super::route_matches;
    use aster_bigtcp::wire::Ipv4Address;

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
}
