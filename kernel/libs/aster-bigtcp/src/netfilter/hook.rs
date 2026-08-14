// SPDX-License-Identifier: MPL-2.0

use smoltcp::wire::{Icmpv4Repr, Ipv4Repr, TcpRepr, UdpRepr};

use super::table;

/// Identifies where an IPv4 packet is observed by the netfilter framework.
///
/// NETFILTER_STAGE7: The names mirror Linux netfilter hook points so future
/// iptables and NAT support can map user-visible chains onto stable kernel
/// insertion points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookPoint {
    PreRouting,
    LocalIn,
    Forward,
    LocalOut,
    PostRouting,
}

impl HookPoint {
    /// 返回内置 IPv4 过滤链使用的稳定索引。
    pub const fn index(self) -> usize {
        match self {
            Self::PreRouting => 0,
            Self::LocalIn => 1,
            Self::Forward => 2,
            Self::LocalOut => 3,
            Self::PostRouting => 4,
        }
    }
}

/// Describes the result of evaluating netfilter rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

impl Verdict {
    /// Returns whether packet processing may continue.
    pub const fn is_accept(self) -> bool {
        matches!(self, Self::Accept)
    }
}

/// Provides immutable packet metadata to hook evaluators.
///
/// NETFILTER_STAGE7: The first stage only needs IPv4 metadata. Later stages can
/// extend this context with transport ports, ICMP type/code, interface IDs, and
/// mutable packet rewrite access for NAT.
#[derive(Clone, Copy, Debug)]
pub struct Ipv4PacketContext<'a> {
    hook_point: HookPoint,
    ipv4_repr: &'a Ipv4Repr,
}

impl<'a> Ipv4PacketContext<'a> {
    /// Creates a packet context for an IPv4 hook evaluation.
    pub const fn new(hook_point: HookPoint, ipv4_repr: &'a Ipv4Repr) -> Self {
        Self {
            hook_point,
            ipv4_repr,
        }
    }

    /// Returns the hook point currently being evaluated.
    pub const fn hook_point(&self) -> HookPoint {
        self.hook_point
    }

    /// Returns the parsed IPv4 header representation.
    pub const fn ipv4_repr(&self) -> &'a Ipv4Repr {
        self.ipv4_repr
    }
}

/// Evaluates IPv4 packet hooks.
///
/// NETFILTER_STAGE10: Empty chains must behave like Linux with no netfilter
/// rules installed, so unmatched packets are accepted by the chain policy.
pub fn evaluate_ipv4(context: Ipv4PacketContext<'_>) -> Verdict {
    table::filter_table().evaluate_ipv4(context)
}

/// Evaluates IPv4 ICMPv4 packet hooks.
///
/// NETFILTER_STAGE10: ICMP-specific metadata is evaluated by built-in filter
/// chains. The hook remains policy-free while chains own rule ordering and
/// default verdicts.
pub fn evaluate_ipv4_icmpv4(context: Ipv4PacketContext<'_>, icmp_repr: &Icmpv4Repr<'_>) -> Verdict {
    table::filter_table().evaluate_ipv4_icmpv4(context, icmp_repr)
}

/// Evaluates IPv4 TCP packet hooks.
///
/// NETFILTER_STAGE20: TCP metadata carries source and destination ports, which
/// enables common iptables rules such as `-p tcp --dport 80 -j DROP`.
pub fn evaluate_ipv4_tcp(context: Ipv4PacketContext<'_>, tcp_repr: &TcpRepr<'_>) -> Verdict {
    table::filter_table().evaluate_ipv4_tcp(context, tcp_repr)
}

/// Evaluates IPv4 UDP packet hooks.
///
/// NETFILTER_STAGE20: UDP metadata carries source and destination ports, which
/// enables DNS-style rules such as `-p udp --dport 53 -j DROP`.
pub fn evaluate_ipv4_udp(context: Ipv4PacketContext<'_>, udp_repr: &UdpRepr) -> Verdict {
    table::filter_table().evaluate_ipv4_udp(context, udp_repr)
}
