// SPDX-License-Identifier: MPL-2.0

//! Stage 2 IPv4 forwarding policy.
//!
//! Routes are currently the directly connected IPv4 prefixes of registered
//! interfaces.  Static routes, a userspace control surface, ICMP-specific
//! errors, conntrack, and NAT are deliberately later stages.

use core::sync::atomic::{AtomicBool, Ordering};

use aster_bigtcp::{
    forwarding::{ForwardedIpv4Packet, ForwardingResult},
    wire::Ipv4Address,
};

use super::iface::iter_all_ifaces;
use crate::prelude::println;

static IPV4_FORWARDING_ENABLED: AtomicBool = AtomicBool::new(false);
static STAGE3_ICMP_MASQUERADE_TEST: AtomicBool = AtomicBool::new(false);
static STAGE3_ICMP_DNAT_TEST: AtomicBool = AtomicBool::new(false);
static STAGE3_ICMP_FORWARD_DROP_TEST: AtomicBool = AtomicBool::new(false);

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
    let egress = iter_all_ifaces()
        .filter(|iface| iface.index() != ingress_ifindex)
        .filter_map(|iface| {
            let address = iface.ipv4_addr()?;
            let prefix_len = iface.prefix_len()?;
            route_matches(destination, address, prefix_len).then_some((prefix_len, iface))
        })
        .max_by_key(|(prefix_len, _)| *prefix_len)
        .map(|(_, iface)| iface);

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
