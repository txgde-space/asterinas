// SPDX-License-Identifier: MPL-2.0

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::wire::{Icmpv4Repr, Ipv4Address, Ipv4Repr, TcpRepr, UdpRepr};

use super::{
    chain::Chain,
    hook::{HookPoint, Ipv4PacketContext, Verdict},
    rule::Action,
};

const STAGE10_DROPPED_ICMP_ECHO_IDENT: u16 = 0x828;
const MAX_OUTPUT_RULES: usize = 12;
const MAX_NAT_RULES: usize = 8;
const IPV4_MIN_HEADER_LEN: usize = 20;

static OUTPUT_RULES: SpinLock<MutableOutputRules, BottomHalfDisabled> =
    SpinLock::new(MutableOutputRules::new());
static NAT_RULES: SpinLock<MutableNatRules, BottomHalfDisabled> =
    SpinLock::new(MutableNatRules::new());

static FILTER_CHAINS: [Chain; 5] = [
    Chain::new(HookPoint::PreRouting, Action::Accept, &[]),
    Chain::new(HookPoint::LocalIn, Action::Accept, &[]),
    Chain::new(HookPoint::Forward, Action::Accept, &[]),
    Chain::new(HookPoint::LocalOut, Action::Accept, &[]),
    Chain::new(HookPoint::PostRouting, Action::Accept, &[]),
];

static FILTER_TABLE: FilterTable = FilterTable {
    chains: &FILTER_CHAINS,
};

/// Stores immutable packet-filtering chains for IPv4 hooks.
///
/// NETFILTER_STAGE10: Stage 9 introduced ordered rules. Stage 10 groups those
/// rules under built-in chains with explicit default policies, which is the
/// shape needed for an iptables-compatible filter table.
#[derive(Debug)]
pub(super) struct FilterTable {
    chains: &'static [Chain],
}

#[derive(Debug)]
struct MutableOutputRules {
    rules: [Option<OutputRule>; MAX_OUTPUT_RULES],
    len: usize,
}

#[derive(Debug)]
struct MutableNatRules {
    rules: [Option<NatRule>; MAX_NAT_RULES],
    len: usize,
}

#[derive(Clone, Copy, Debug)]
struct OutputRule {
    protocol: OutputRuleProtocol,
    icmp_echo_ident: Option<u16>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    action: Action,
    packets: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct NatRule {
    chain: NatRuleChain,
    protocol: Option<OutputRuleProtocol>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    target: NatRuleTarget,
    to_addr: Option<Ipv4Address>,
    to_port: Option<u16>,
    packets: u64,
    bytes: u64,
}

impl NatRule {
    const fn new(
        chain: NatRuleChain,
        protocol: Option<OutputRuleProtocol>,
        src_addr: Option<Ipv4Address>,
        dst_addr: Option<Ipv4Address>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        target: NatRuleTarget,
        to_addr: Option<Ipv4Address>,
        to_port: Option<u16>,
    ) -> Self {
        Self {
            chain,
            protocol,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            target,
            to_addr,
            to_port,
            packets: 0,
            bytes: 0,
        }
    }

    fn matches_common_ipv4(self, ipv4_repr: &Ipv4Repr) -> bool {
        if self
            .src_addr
            .is_some_and(|src_addr| src_addr != ipv4_repr.src_addr)
        {
            return false;
        }

        if self
            .dst_addr
            .is_some_and(|dst_addr| dst_addr != ipv4_repr.dst_addr)
        {
            return false;
        }

        true
    }

    fn matches_postrouting_transport(
        self,
        protocol: OutputRuleProtocol,
        ipv4_repr: &Ipv4Repr,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        if self.chain != NatRuleChain::PostRouting || !self.matches_common_ipv4(ipv4_repr) {
            return false;
        }

        if self.protocol.is_some_and(|expected| expected != protocol) {
            return false;
        }

        if self.src_port.is_some_and(|expected| expected != src_port) {
            return false;
        }

        if self.dst_port.is_some_and(|expected| expected != dst_port) {
            return false;
        }

        matches!(self.target, NatRuleTarget::Masquerade | NatRuleTarget::Snat)
    }

    fn matches_postrouting_icmp(self, ipv4_repr: &Ipv4Repr) -> bool {
        if self.chain != NatRuleChain::PostRouting || !self.matches_common_ipv4(ipv4_repr) {
            return false;
        }

        if self
            .protocol
            .is_some_and(|expected| expected != OutputRuleProtocol::Icmp)
        {
            return false;
        }

        self.src_port.is_none()
            && self.dst_port.is_none()
            && matches!(self.target, NatRuleTarget::Masquerade | NatRuleTarget::Snat)
    }

    fn record_match(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }
}

impl OutputRule {
    const fn icmp_echo(
        ident: Option<u16>,
        src_addr: Option<Ipv4Address>,
        dst_addr: Option<Ipv4Address>,
        action: Action,
    ) -> Self {
        Self {
            protocol: OutputRuleProtocol::Icmp,
            icmp_echo_ident: ident,
            src_addr,
            dst_addr,
            src_port: None,
            dst_port: None,
            action,
            packets: 0,
            bytes: 0,
        }
    }

    const fn transport(
        protocol: OutputRuleProtocol,
        src_addr: Option<Ipv4Address>,
        dst_addr: Option<Ipv4Address>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        action: Action,
    ) -> Self {
        Self {
            protocol,
            icmp_echo_ident: None,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            action,
            packets: 0,
            bytes: 0,
        }
    }

    fn matches_common_ipv4(self, context: Ipv4PacketContext<'_>) -> bool {
        if self
            .src_addr
            .is_some_and(|src_addr| src_addr != context.ipv4_repr().src_addr)
        {
            return false;
        }

        if self
            .dst_addr
            .is_some_and(|dst_addr| dst_addr != context.ipv4_repr().dst_addr)
        {
            return false;
        }

        true
    }

    fn matches_icmp_echo(self, context: Ipv4PacketContext<'_>, ident: u16) -> bool {
        if self.protocol != OutputRuleProtocol::Icmp || !self.matches_common_ipv4(context) {
            return false;
        }

        !self
            .icmp_echo_ident
            .is_some_and(|expected_ident| expected_ident != ident)
    }

    fn matches_transport(
        self,
        protocol: OutputRuleProtocol,
        context: Ipv4PacketContext<'_>,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        if self.protocol != protocol || !self.matches_common_ipv4(context) {
            return false;
        }

        if self
            .src_port
            .is_some_and(|expected_port| expected_port != src_port)
        {
            return false;
        }

        if self
            .dst_port
            .is_some_and(|expected_port| expected_port != dst_port)
        {
            return false;
        }

        true
    }

    fn record_match(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }

    fn zero_counters(&mut self) {
        self.packets = 0;
        self.bytes = 0;
    }
}

impl MutableNatRules {
    const fn new() -> Self {
        Self {
            rules: [None, None, None, None, None, None, None, None],
            len: 0,
        }
    }

    fn append_rule(&mut self, rule: NatRule) -> bool {
        if self.len == MAX_NAT_RULES {
            return false;
        }

        self.rules[self.len] = Some(rule);
        self.len += 1;
        true
    }

    fn flush(&mut self, chain: Option<NatRuleChain>) {
        let mut next_len = 0;

        for index in 0..self.len {
            let Some(rule) = self.rules[index] else {
                continue;
            };

            if chain.is_some_and(|chain| chain == rule.chain) || chain.is_none() {
                continue;
            }

            self.rules[next_len] = Some(rule);
            next_len += 1;
        }

        for rule in &mut self.rules[next_len..] {
            *rule = None;
        }
        self.len = next_len;
    }

    fn len(&self) -> usize {
        self.len
    }

    fn rewrite_postrouting_transport(
        &mut self,
        protocol: OutputRuleProtocol,
        mut ipv4_repr: Ipv4Repr,
        src_port: u16,
        dst_port: u16,
        masquerade_addr: Option<Ipv4Address>,
    ) -> (Ipv4Repr, Option<u16>) {
        let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(ipv4_repr.payload_len);

        for rule in &mut self.rules[..self.len] {
            let Some(rule) = rule.as_mut() else {
                continue;
            };

            if !rule.matches_postrouting_transport(protocol, &ipv4_repr, src_port, dst_port) {
                continue;
            }

            let new_src_addr = match rule.target {
                NatRuleTarget::Masquerade => masquerade_addr,
                NatRuleTarget::Snat => rule.to_addr,
                NatRuleTarget::Dnat => None,
            };
            let Some(new_src_addr) = new_src_addr else {
                return (ipv4_repr, None);
            };

            rule.record_match(packet_len);
            ipv4_repr.src_addr = new_src_addr;
            return (ipv4_repr, rule.to_port);
        }

        (ipv4_repr, None)
    }

    fn rewrite_postrouting_icmp(
        &mut self,
        mut ipv4_repr: Ipv4Repr,
        masquerade_addr: Option<Ipv4Address>,
    ) -> Ipv4Repr {
        let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(ipv4_repr.payload_len);

        for rule in &mut self.rules[..self.len] {
            let Some(rule) = rule.as_mut() else {
                continue;
            };

            if !rule.matches_postrouting_icmp(&ipv4_repr) {
                continue;
            }

            let new_src_addr = match rule.target {
                NatRuleTarget::Masquerade => masquerade_addr,
                NatRuleTarget::Snat => rule.to_addr,
                NatRuleTarget::Dnat => None,
            };
            let Some(new_src_addr) = new_src_addr else {
                return ipv4_repr;
            };

            rule.record_match(packet_len);
            ipv4_repr.src_addr = new_src_addr;
            return ipv4_repr;
        }

        ipv4_repr
    }
}

impl MutableOutputRules {
    const fn new() -> Self {
        Self {
            rules: [
                Some(OutputRule::icmp_echo(
                    Some(STAGE10_DROPPED_ICMP_ECHO_IDENT),
                    None,
                    None,
                    Action::Drop,
                )),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            len: 1,
        }
    }

    fn append_icmp_echo(
        &mut self,
        ident: Option<u16>,
        src_addr: Option<Ipv4Address>,
        dst_addr: Option<Ipv4Address>,
        target: OutputRuleTarget,
    ) -> bool {
        self.append_rule(OutputRule::icmp_echo(
            ident,
            src_addr,
            dst_addr,
            target.into_action(),
        ))
    }

    fn append_transport(
        &mut self,
        protocol: OutputRuleProtocol,
        src_addr: Option<Ipv4Address>,
        dst_addr: Option<Ipv4Address>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        target: OutputRuleTarget,
    ) -> bool {
        self.append_rule(OutputRule::transport(
            protocol,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            target.into_action(),
        ))
    }

    fn append_rule(&mut self, rule: OutputRule) -> bool {
        if self.len == MAX_OUTPUT_RULES {
            return false;
        }

        self.rules[self.len] = Some(rule);
        self.len += 1;
        true
    }

    fn delete(&mut self, index: usize) -> bool {
        if index >= self.len {
            return false;
        }

        for idx in index..self.len - 1 {
            self.rules[idx] = self.rules[idx + 1];
        }
        self.len -= 1;
        self.rules[self.len] = None;
        true
    }

    fn flush(&mut self) {
        for rule in &mut self.rules {
            *rule = None;
        }
        self.len = 0;
    }

    fn zero_counters(&mut self) {
        for rule in &mut self.rules[..self.len] {
            let Some(rule) = rule.as_mut() else {
                continue;
            };

            rule.zero_counters();
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn evaluate_matching_icmp_echo(
        &mut self,
        context: Ipv4PacketContext<'_>,
        ident: u16,
        bytes: usize,
    ) -> Option<Verdict> {
        self.evaluate_first_match(bytes, |rule| rule.matches_icmp_echo(context, ident))
    }

    fn evaluate_matching_transport(
        &mut self,
        protocol: OutputRuleProtocol,
        context: Ipv4PacketContext<'_>,
        src_port: u16,
        dst_port: u16,
        bytes: usize,
    ) -> Option<Verdict> {
        self.evaluate_first_match(bytes, |rule| {
            rule.matches_transport(protocol, context, src_port, dst_port)
        })
    }

    fn evaluate_first_match(
        &mut self,
        bytes: usize,
        matches_rule: impl Fn(OutputRule) -> bool,
    ) -> Option<Verdict> {
        for rule in &mut self.rules[..self.len] {
            let Some(rule) = rule.as_mut() else {
                continue;
            };

            if matches_rule(*rule) {
                rule.record_match(bytes);
                return Some(rule.action.into());
            }
        }

        None
    }
}

/// Describes the protocol matched by a mutable OUTPUT rule.
///
/// NETFILTER_STAGE20: The table now covers ICMP Echo plus TCP/UDP port
/// matchers, which is enough for common firewall demonstrations such as
/// dropping HTTP or DNS-like traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputRuleProtocol {
    Icmp,
    Tcp,
    Udp,
}

/// Describes the terminal target selected by a mutable OUTPUT rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputRuleTarget {
    Accept,
    Drop,
}

/// Describes a mutable NAT chain.
///
/// NETFILTER_STAGE21: NAT support starts with the two IPv4 chains used by
/// classic iptables NAT examples. Stage 22 can attach these rules to packet
/// rewriting without changing the userspace control syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatRuleChain {
    PreRouting,
    PostRouting,
}

/// Describes the NAT target selected by a mutable rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatRuleTarget {
    Dnat,
    Masquerade,
    Snat,
}

impl OutputRuleTarget {
    const fn into_action(self) -> Action {
        match self {
            Self::Accept => Action::Accept,
            Self::Drop => Action::Drop,
        }
    }
}

impl FilterTable {
    /// Evaluates generic IPv4 rules and returns the first matching verdict.
    pub(super) fn evaluate_ipv4(&self, context: Ipv4PacketContext<'_>) -> Verdict {
        let Some(chain) = self.find_chain(context.hook_point()) else {
            return Verdict::Accept;
        };

        chain.evaluate_ipv4(context)
    }

    fn find_chain(&self, hook_point: HookPoint) -> Option<Chain> {
        for chain in self.chains {
            if chain.handles(hook_point) {
                return Some(*chain);
            }
        }

        None
    }

    /// Evaluates IPv4 ICMPv4 rules and returns the first matching verdict.
    pub(super) fn evaluate_ipv4_icmpv4(
        &self,
        context: Ipv4PacketContext<'_>,
        icmp_repr: &Icmpv4Repr<'_>,
    ) -> Verdict {
        if context.hook_point() == HookPoint::LocalOut {
            let Icmpv4Repr::EchoRequest { ident, .. } = icmp_repr else {
                return Verdict::Accept;
            };

            let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(context.ipv4_repr().payload_len);
            if let Some(verdict) = OUTPUT_RULES
                .lock()
                .evaluate_matching_icmp_echo(context, *ident, packet_len)
            {
                return verdict;
            }
        }

        let Some(chain) = self.find_chain(context.hook_point()) else {
            return Verdict::Accept;
        };

        chain.evaluate_ipv4_icmpv4(context, icmp_repr)
    }

    /// Evaluates IPv4 TCP rules and returns the first matching verdict.
    pub(super) fn evaluate_ipv4_tcp(
        &self,
        context: Ipv4PacketContext<'_>,
        tcp_repr: &TcpRepr<'_>,
    ) -> Verdict {
        self.evaluate_ipv4_transport(
            context,
            OutputRuleProtocol::Tcp,
            tcp_repr.src_port,
            tcp_repr.dst_port,
        )
    }

    /// Evaluates IPv4 UDP rules and returns the first matching verdict.
    pub(super) fn evaluate_ipv4_udp(
        &self,
        context: Ipv4PacketContext<'_>,
        udp_repr: &UdpRepr,
    ) -> Verdict {
        self.evaluate_ipv4_transport(
            context,
            OutputRuleProtocol::Udp,
            udp_repr.src_port,
            udp_repr.dst_port,
        )
    }

    fn evaluate_ipv4_transport(
        &self,
        context: Ipv4PacketContext<'_>,
        protocol: OutputRuleProtocol,
        src_port: u16,
        dst_port: u16,
    ) -> Verdict {
        // NETFILTER_STAGE20: TCP/UDP rules use the same first-match OUTPUT
        // chain semantics as ICMP rules, but match transport ports.
        if context.hook_point() == HookPoint::LocalOut {
            let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(context.ipv4_repr().payload_len);
            if let Some(verdict) = OUTPUT_RULES
                .lock()
                .evaluate_matching_transport(protocol, context, src_port, dst_port, packet_len)
            {
                return verdict;
            }
        }

        let Some(chain) = self.find_chain(context.hook_point()) else {
            return Verdict::Accept;
        };

        chain.evaluate_ipv4(context)
    }
}

/// Returns the static IPv4 filter table.
