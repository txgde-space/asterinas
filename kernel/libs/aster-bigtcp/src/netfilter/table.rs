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
pub(super) fn filter_table() -> &'static FilterTable {
    &FILTER_TABLE
}

/// Writes a userspace snapshot of the IPv4 filter table.
///
/// NETFILTER_STAGE20: The snapshot now includes ICMP, TCP, and UDP matchers
/// plus optional source/destination ports.
pub fn write_filter_table_snapshot(writer: &mut impl core::fmt::Write) -> core::fmt::Result {
    writeln!(writer, "table filter")?;
    writeln!(writer, "chain PREROUTING policy ACCEPT")?;
    writeln!(writer, "chain INPUT policy ACCEPT")?;
    writeln!(writer, "chain FORWARD policy ACCEPT")?;
    writeln!(writer, "chain OUTPUT policy ACCEPT")?;

    let output_rules = OUTPUT_RULES.lock();
    for (index, rule) in output_rules.rules[..output_rules.len()]
        .iter()
        .flatten()
        .enumerate()
    {
        writeln!(
            writer,
            "  rule {} pkts {} bytes {} match{}{} {}{}{} target {}",
            index,
            rule.packets,
            rule.bytes,
            FormatIpv4Matcher::new(" src", rule.src_addr),
            FormatIpv4Matcher::new(" dst", rule.dst_addr),
            FormatProtocolMatcher(*rule),
            FormatPortMatcher::new(" sport", rule.src_port),
            FormatPortMatcher::new(" dport", rule.dst_port),
            FormatAction(rule.action),
        )?;
    }

    writeln!(writer, "chain POSTROUTING policy ACCEPT")?;
    writeln!(
        writer,
        "state stage20-output-rule-count {}",
        output_rules.len()
    )?;
    drop(output_rules);

    // NETFILTER_STAGE21: NAT rules are intentionally rendered in the same
    // procfs snapshot as the filter table so the small `iptables` shim can
    // implement `-t nat -L` without a second kernel ABI.
    writeln!(writer, "table nat")?;
    writeln!(writer, "chain PREROUTING policy ACCEPT")?;

    let nat_rules = NAT_RULES.lock();
    for (index, rule) in nat_rules.rules[..nat_rules.len()]
        .iter()
        .flatten()
        .enumerate()
    {
        writeln!(
            writer,
            "  rule {} chain {} pkts {} bytes {} match{}{}{}{}{} target {}{}{}",
            index,
            FormatNatChain(rule.chain),
            rule.packets,
            rule.bytes,
            FormatOptionalProtocolMatcher(rule.protocol),
            FormatIpv4Matcher::new(" src", rule.src_addr),
            FormatIpv4Matcher::new(" dst", rule.dst_addr),
            FormatPortMatcher::new(" sport", rule.src_port),
            FormatPortMatcher::new(" dport", rule.dst_port),
            FormatNatTarget(rule.target),
            FormatNatToAddress::new(rule.target, rule.to_addr),
            FormatNatToPort(rule.to_port),
        )?;
    }

    writeln!(writer, "chain POSTROUTING policy ACCEPT")?;
    writeln!(writer, "state stage21-nat-rule-count {}", nat_rules.len())
}

/// Appends an OUTPUT-chain ICMP Echo rule.
pub fn append_output_icmp_echo_rule(
    ident: Option<u16>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    target: OutputRuleTarget,
) -> bool {
    OUTPUT_RULES
        .lock()
        .append_icmp_echo(ident, src_addr, dst_addr, target)
}

/// Appends an OUTPUT-chain TCP or UDP rule.
pub fn append_output_transport_rule(
    protocol: OutputRuleProtocol,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    target: OutputRuleTarget,
) -> bool {
    OUTPUT_RULES
        .lock()
        .append_transport(protocol, src_addr, dst_addr, src_port, dst_port, target)
}

/// Deletes one OUTPUT-chain rule by index.
pub fn delete_output_rule(index: usize) -> bool {
    OUTPUT_RULES.lock().delete(index)
}

/// Flushes all OUTPUT-chain rules.
pub fn flush_output_rules() {
    OUTPUT_RULES.lock().flush();
}

/// Clears packet and byte counters from all OUTPUT-chain rules.
pub fn zero_output_rule_counters() {
    OUTPUT_RULES.lock().zero_counters();
}

/// Appends a NAT control-plane rule.
pub fn append_nat_rule(
    chain: NatRuleChain,
    protocol: Option<OutputRuleProtocol>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    target: NatRuleTarget,
    to_addr: Option<Ipv4Address>,
    to_port: Option<u16>,
) -> bool {
    NAT_RULES.lock().append_rule(NatRule::new(
        chain, protocol, src_addr, dst_addr, src_port, dst_port, target, to_addr, to_port,
    ))
}

/// Flushes NAT rules from one chain or from the whole NAT table.
pub fn flush_nat_rules(chain: Option<NatRuleChain>) {
    NAT_RULES.lock().flush(chain);
}

/// Applies POSTROUTING NAT to an IPv4 TCP packet representation.
///
/// NETFILTER_STAGE22: The prototype NAT data path rewrites the representation
/// before smoltcp emits bytes, so IPv4/TCP checksums are recalculated by the
/// existing packet emitter.
pub fn rewrite_ipv4_tcp_postrouting<'a>(
    ipv4_repr: Ipv4Repr,
    mut tcp_repr: TcpRepr<'a>,
    masquerade_addr: Option<Ipv4Address>,
) -> (Ipv4Repr, TcpRepr<'a>) {
    let (ipv4_repr, src_port) = NAT_RULES.lock().rewrite_postrouting_transport(
        OutputRuleProtocol::Tcp,
        ipv4_repr,
        tcp_repr.src_port,
        tcp_repr.dst_port,
        masquerade_addr,
    );
    if let Some(src_port) = src_port {
        tcp_repr.src_port = src_port;
    }

    (ipv4_repr, tcp_repr)
}

/// Applies POSTROUTING NAT to an IPv4 UDP packet representation.
pub fn rewrite_ipv4_udp_postrouting(
    ipv4_repr: Ipv4Repr,
    mut udp_repr: UdpRepr,
    masquerade_addr: Option<Ipv4Address>,
) -> (Ipv4Repr, UdpRepr) {
    let (ipv4_repr, src_port) = NAT_RULES.lock().rewrite_postrouting_transport(
        OutputRuleProtocol::Udp,
        ipv4_repr,
        udp_repr.src_port,
        udp_repr.dst_port,
        masquerade_addr,
    );
    if let Some(src_port) = src_port {
        udp_repr.src_port = src_port;
    }

    (ipv4_repr, udp_repr)
}

/// Applies POSTROUTING NAT to an IPv4 ICMP packet representation.
pub fn rewrite_ipv4_icmp_postrouting(
    ipv4_repr: Ipv4Repr,
    masquerade_addr: Option<Ipv4Address>,
) -> Ipv4Repr {
    NAT_RULES
        .lock()
        .rewrite_postrouting_icmp(ipv4_repr, masquerade_addr)
}

struct FormatIpv4Matcher {
    label: &'static str,
    addr: Option<Ipv4Address>,
}

impl FormatIpv4Matcher {
    const fn new(label: &'static str, addr: Option<Ipv4Address>) -> Self {
        Self { label, addr }
    }
}

impl core::fmt::Display for FormatIpv4Matcher {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Some(addr) = self.addr else {
            return Ok(());
        };
        let octets = addr.octets();

        write!(
            formatter,
            "{} {}.{}.{}.{}",
            self.label, octets[0], octets[1], octets[2], octets[3]
        )
    }
}

struct FormatPortMatcher {
    label: &'static str,
    port: Option<u16>,
}

impl FormatPortMatcher {
    const fn new(label: &'static str, port: Option<u16>) -> Self {
        Self { label, port }
    }
}

impl core::fmt::Display for FormatPortMatcher {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Some(port) = self.port else {
            return Ok(());
        };

        write!(formatter, "{} {}", self.label, port)
    }
}

struct FormatProtocolMatcher(OutputRule);

impl core::fmt::Display for FormatProtocolMatcher {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0.protocol {
            OutputRuleProtocol::Icmp => match self.0.icmp_echo_ident {
                Some(ident) => write!(formatter, "icmp-echo-ident 0x{:04x}", ident),
                None => formatter.write_str("icmp-type echo-request"),
            },
            OutputRuleProtocol::Tcp => formatter.write_str("tcp"),
            OutputRuleProtocol::Udp => formatter.write_str("udp"),
        }
    }
}

struct FormatOptionalProtocolMatcher(Option<OutputRuleProtocol>);

impl core::fmt::Display for FormatOptionalProtocolMatcher {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Some(protocol) = self.0 else {
            return formatter.write_str(" all");
        };

        match protocol {
            OutputRuleProtocol::Icmp => formatter.write_str(" icmp"),
            OutputRuleProtocol::Tcp => formatter.write_str(" tcp"),
            OutputRuleProtocol::Udp => formatter.write_str(" udp"),
        }
    }
}

struct FormatNatChain(NatRuleChain);

impl core::fmt::Display for FormatNatChain {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            NatRuleChain::PreRouting => formatter.write_str("PREROUTING"),
            NatRuleChain::PostRouting => formatter.write_str("POSTROUTING"),
        }
    }
}

struct FormatNatTarget(NatRuleTarget);

impl core::fmt::Display for FormatNatTarget {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            NatRuleTarget::Dnat => formatter.write_str("DNAT"),
            NatRuleTarget::Masquerade => formatter.write_str("MASQUERADE"),
            NatRuleTarget::Snat => formatter.write_str("SNAT"),
        }
    }
}

struct FormatNatToAddress {
    target: NatRuleTarget,
    addr: Option<Ipv4Address>,
}

impl FormatNatToAddress {
    const fn new(target: NatRuleTarget, addr: Option<Ipv4Address>) -> Self {
        Self { target, addr }
    }
}

impl core::fmt::Display for FormatNatToAddress {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Some(addr) = self.addr else {
            return Ok(());
        };
        let octets = addr.octets();

        match self.target {
            NatRuleTarget::Dnat => write!(
                formatter,
                " to-destination {}.{}.{}.{}",
                octets[0], octets[1], octets[2], octets[3]
            ),
            NatRuleTarget::Snat => write!(
                formatter,
                " to-source {}.{}.{}.{}",
                octets[0], octets[1], octets[2], octets[3]
            ),
            NatRuleTarget::Masquerade => Ok(()),
        }
    }
}

struct FormatNatToPort(Option<u16>);

impl core::fmt::Display for FormatNatToPort {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Some(port) = self.0 else {
            return Ok(());
        };

        write!(formatter, ":{}", port)
    }
}

struct FormatAction(Action);

impl core::fmt::Display for FormatAction {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Action::Accept => formatter.write_str("ACCEPT"),
            Action::Drop => formatter.write_str("DROP"),
        }
    }
}
