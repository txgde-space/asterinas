// SPDX-License-Identifier: MPL-2.0

//! IPv6 filter hooks for the small netfilter-compatible data path.
//!
//! Stage 11 deliberately keeps the matcher set bounded and allocation-free:
//! source/destination address, next-header protocol, and ICMPv6 type are
//! enough to demonstrate INPUT/FORWARD/OUTPUT policy without pretending to
//! implement every ip6tables extension.

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::wire::Ipv6Address;

use super::{hook::HookPoint, rule::Action, Verdict};

const MAX_IPV6_FILTER_RULES: usize = 32;

static IPV6_FILTER_RULES: [SpinLock<MutableIpv6Rules, BottomHalfDisabled>; 5] = [
    SpinLock::new(MutableIpv6Rules::new()),
    SpinLock::new(MutableIpv6Rules::new()),
    SpinLock::new(MutableIpv6Rules::new()),
    SpinLock::new(MutableIpv6Rules::new()),
    SpinLock::new(MutableIpv6Rules::new()),
];

/// Metadata made available to an IPv6 filter hook.
#[derive(Clone, Copy, Debug)]
pub struct Ipv6PacketContext {
    hook_point: HookPoint,
    src_addr: Ipv6Address,
    dst_addr: Ipv6Address,
    next_header: u8,
    icmpv6_type: Option<u8>,
    payload_len: usize,
}

impl Ipv6PacketContext {
    pub const fn new(
        hook_point: HookPoint,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        next_header: u8,
        icmpv6_type: Option<u8>,
        payload_len: usize,
    ) -> Self {
        Self {
            hook_point,
            src_addr,
            dst_addr,
            next_header,
            icmpv6_type,
            payload_len,
        }
    }

    pub const fn hook_point(self) -> HookPoint {
        self.hook_point
    }

    pub const fn src_addr(self) -> Ipv6Address {
        self.src_addr
    }

    pub const fn dst_addr(self) -> Ipv6Address {
        self.dst_addr
    }

    pub const fn next_header(self) -> u8 {
        self.next_header
    }

    pub const fn icmpv6_type(self) -> Option<u8> {
        self.icmpv6_type
    }

    pub const fn payload_len(self) -> usize {
        self.payload_len
    }
}

/// Protocol selectors understood by the Stage 11 IPv6 matcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6RuleProtocol {
    Any,
    Icmpv6,
    Tcp,
    Udp,
}

/// Terminal action for an IPv6 filter rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6RuleTarget {
    Accept,
    Drop,
}

#[derive(Clone, Copy, Debug)]
struct Ipv6Rule {
    protocol: Ipv6RuleProtocol,
    src_addr: Option<Ipv6Address>,
    dst_addr: Option<Ipv6Address>,
    icmpv6_type: Option<u8>,
    action: Action,
    packets: u64,
    bytes: u64,
}

impl Ipv6Rule {
    const fn new(
        protocol: Ipv6RuleProtocol,
        src_addr: Option<Ipv6Address>,
        dst_addr: Option<Ipv6Address>,
        icmpv6_type: Option<u8>,
        action: Action,
    ) -> Self {
        Self {
            protocol,
            src_addr,
            dst_addr,
            icmpv6_type,
            action,
            packets: 0,
            bytes: 0,
        }
    }

    fn matches(self, context: Ipv6PacketContext) -> bool {
        if self
            .src_addr
            .is_some_and(|address| address != context.src_addr())
            || self
                .dst_addr
                .is_some_and(|address| address != context.dst_addr())
        {
            return false;
        }

        let protocol_matches = match self.protocol {
            Ipv6RuleProtocol::Any => true,
            Ipv6RuleProtocol::Icmpv6 => context.next_header() == 58,
            Ipv6RuleProtocol::Tcp => context.next_header() == 6,
            Ipv6RuleProtocol::Udp => context.next_header() == 17,
        };
        protocol_matches
            && self
                .icmpv6_type
                .is_none_or(|icmp_type| context.icmpv6_type() == Some(icmp_type))
    }

    fn record_match(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }
}

#[derive(Debug)]
struct MutableIpv6Rules {
    rules: [Option<Ipv6Rule>; MAX_IPV6_FILTER_RULES],
    len: usize,
    policy: Action,
}

impl MutableIpv6Rules {
    const fn new() -> Self {
        Self {
            rules: [None; MAX_IPV6_FILTER_RULES],
            len: 0,
            policy: Action::Accept,
        }
    }

    fn append(&mut self, rule: Ipv6Rule) -> bool {
        if self.len == MAX_IPV6_FILTER_RULES {
            return false;
        }
        self.rules[self.len] = Some(rule);
        self.len += 1;
        true
    }

    fn flush(&mut self) {
        for rule in &mut self.rules {
            *rule = None;
        }
        self.len = 0;
    }

    fn zero(&mut self) {
        for rule in &mut self.rules[..self.len] {
            if let Some(rule) = rule.as_mut() {
                rule.packets = 0;
                rule.bytes = 0;
            }
        }
    }
}

/// Evaluates one IPv6 packet at an INPUT, FORWARD, or OUTPUT hook.
pub fn evaluate_ipv6(context: Ipv6PacketContext) -> Verdict {
    let mut rules = IPV6_FILTER_RULES[context.hook_point().index()].lock();
    let rule_count = rules.len;
    for rule in &mut rules.rules[..rule_count] {
        let Some(rule) = rule.as_mut() else {
            continue;
        };
        if rule.matches(context) {
            rule.record_match(context.payload_len().saturating_add(40));
            return rule.action.into();
        }
    }
    rules.policy.into()
}

/// Appends one bounded IPv6 filter rule to a built-in chain.
pub fn append_filter_rule(
    hook_point: HookPoint,
    protocol: Ipv6RuleProtocol,
    src_addr: Option<Ipv6Address>,
    dst_addr: Option<Ipv6Address>,
    icmpv6_type: Option<u8>,
    target: Ipv6RuleTarget,
) -> bool {
    IPV6_FILTER_RULES[hook_point.index()].lock().append(Ipv6Rule::new(
        protocol,
        src_addr,
        dst_addr,
        icmpv6_type,
        target.into(),
    ))
}

/// Changes the default policy of one IPv6 filter chain.
pub fn set_chain_policy(hook_point: HookPoint, target: Ipv6RuleTarget) {
    IPV6_FILTER_RULES[hook_point.index()].lock().policy = target.into();
}

/// Removes IPv6 rules from one chain, or all chains when `None` is supplied.
pub fn flush_rules(hook_point: Option<HookPoint>) {
    for (index, rules) in IPV6_FILTER_RULES.iter().enumerate() {
        if hook_point.is_none_or(|hook| hook.index() == index) {
            rules.lock().flush();
        }
    }
}

/// Clears IPv6 rule counters in one chain, or all chains when `None` is supplied.
pub fn zero_counters(hook_point: Option<HookPoint>) {
    for (index, rules) in IPV6_FILTER_RULES.iter().enumerate() {
        if hook_point.is_none_or(|hook| hook.index() == index) {
            rules.lock().zero();
        }
    }
}

/// Renders the IPv6 table in the existing `/proc/netfilter_rules` snapshot.
pub fn write_snapshot(writer: &mut impl core::fmt::Write) -> core::fmt::Result {
    writeln!(writer, "table filter6")?;
    for hook_point in [
        HookPoint::PreRouting,
        HookPoint::LocalIn,
        HookPoint::Forward,
        HookPoint::LocalOut,
        HookPoint::PostRouting,
    ] {
        let rules = IPV6_FILTER_RULES[hook_point.index()].lock();
        writeln!(
            writer,
            "chain6 {} policy {}",
            format_hook(hook_point),
            format_action(rules.policy)
        )?;
        for (index, rule) in rules.rules[..rules.len].iter().flatten().enumerate() {
            writeln!(
                writer,
                "  rule6 {} pkts {} bytes {} proto {} src {:?} dst {:?} icmpv6-type {:?} target {}",
                index,
                rule.packets,
                rule.bytes,
                format_protocol(rule.protocol),
                rule.src_addr,
                rule.dst_addr,
                rule.icmpv6_type,
                format_action(rule.action),
            )?;
        }
        writeln!(
            writer,
            "state stage11-{}-rule-count {}",
            format_hook(hook_point),
            rules.len
        )?;
    }
    Ok(())
}

impl From<Ipv6RuleTarget> for Action {
    fn from(target: Ipv6RuleTarget) -> Self {
        match target {
            Ipv6RuleTarget::Accept => Self::Accept,
            Ipv6RuleTarget::Drop => Self::Drop,
        }
    }
}

fn format_hook(hook_point: HookPoint) -> &'static str {
    match hook_point {
        HookPoint::PreRouting => "PREROUTING",
        HookPoint::LocalIn => "INPUT",
        HookPoint::Forward => "FORWARD",
        HookPoint::LocalOut => "OUTPUT",
        HookPoint::PostRouting => "POSTROUTING",
    }
}

fn format_protocol(protocol: Ipv6RuleProtocol) -> &'static str {
    match protocol {
        Ipv6RuleProtocol::Any => "all",
        Ipv6RuleProtocol::Icmpv6 => "ipv6-icmp",
        Ipv6RuleProtocol::Tcp => "tcp",
        Ipv6RuleProtocol::Udp => "udp",
    }
}

fn format_action(action: Action) -> &'static str {
    match action {
        Action::Accept => "ACCEPT",
        Action::Drop => "DROP",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmpv6_rule_matches_only_echo_requests() {
        flush_rules(None);
        let src = Ipv6Address::new(0xfd00, 0, 0, 2, 0, 0, 0, 2);
        let dst = Ipv6Address::new(0xfd00, 0, 0, 3, 0, 0, 0, 2);
        assert!(append_filter_rule(
            HookPoint::Forward,
            Ipv6RuleProtocol::Icmpv6,
            Some(src),
            Some(dst),
            Some(128),
            Ipv6RuleTarget::Drop,
        ));
        let context = Ipv6PacketContext::new(HookPoint::Forward, src, dst, 58, Some(128), 64);
        assert_eq!(evaluate_ipv6(context), Verdict::Drop);
        let reply = Ipv6PacketContext::new(HookPoint::Forward, dst, src, 58, Some(129), 64);
        assert_eq!(evaluate_ipv6(reply), Verdict::Accept);
        flush_rules(None);
    }
}
