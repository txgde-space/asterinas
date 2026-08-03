// SPDX-License-Identifier: MPL-2.0

//! Bounded stateful IPv6 NAT (NAT66) for the forwarding data path.
//!
//! This is deliberately a small, deterministic subset of ip6tables' nat
//! table.  It supports address-only SNAT, MASQUERADE, and DNAT for ICMPv6,
//! TCP, and UDP.  A fixed-size connection table keeps the early kernel data
//! path allocation-free and makes failure behavior explicit: once the table
//! is full, a new translation is skipped instead of dropping an unrelated
//! packet.

use aster_softirq::BottomHalfDisabled;
use core::fmt::Write as _;
use ostd::sync::SpinLock;
use smoltcp::wire::Ipv6Address;

use super::ipv6::Ipv6RuleProtocol;
use crate::forwarding::ForwardedIpv6Packet;

const MAX_IPV6_NAT_RULES: usize = 32;
const MAX_IPV6_NAT_CONNECTIONS: usize = 64;

static IPV6_NAT: SpinLock<MutableIpv6Nat, BottomHalfDisabled> =
    SpinLock::new(MutableIpv6Nat::new());

/// The two IPv6 nat-table hooks implemented by this stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6NatRuleChain {
    PreRouting,
    PostRouting,
}

/// Address translation target understood by the Stage 12 control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6NatRuleTarget {
    Dnat,
    Masquerade,
    Snat,
}

#[derive(Clone, Copy, Debug)]
struct Ipv6NatRule {
    chain: Ipv6NatRuleChain,
    protocol: Ipv6RuleProtocol,
    src_addr: Option<Ipv6Address>,
    dst_addr: Option<Ipv6Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    target: Ipv6NatRuleTarget,
    to_addr: Option<Ipv6Address>,
    packets: u64,
    bytes: u64,
}

impl Ipv6NatRule {
    const fn new(
        chain: Ipv6NatRuleChain,
        protocol: Ipv6RuleProtocol,
        src_addr: Option<Ipv6Address>,
        dst_addr: Option<Ipv6Address>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        target: Ipv6NatRuleTarget,
        to_addr: Option<Ipv6Address>,
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
            packets: 0,
            bytes: 0,
        }
    }

    fn matches(self, chain: Ipv6NatRuleChain, tuple: Ipv6Tuple) -> bool {
        if self.chain != chain
            || self.src_addr.is_some_and(|address| address != tuple.src_addr)
            || self.dst_addr.is_some_and(|address| address != tuple.dst_addr)
            || self.src_port.is_some_and(|port| Some(port) != tuple.src_port)
            || self.dst_port.is_some_and(|port| Some(port) != tuple.dst_port)
        {
            return false;
        }

        match self.protocol {
            Ipv6RuleProtocol::Any => true,
            Ipv6RuleProtocol::Icmpv6 => tuple.next_header == 58,
            Ipv6RuleProtocol::Tcp => tuple.next_header == 6,
            Ipv6RuleProtocol::Udp => tuple.next_header == 17,
        }
    }

    fn record(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }
}

#[derive(Clone, Copy, Debug)]
struct Ipv6Tuple {
    src_addr: Ipv6Address,
    dst_addr: Ipv6Address,
    next_header: u8,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

impl Ipv6Tuple {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 || bytes[0] >> 4 != 6 {
            return None;
        }
        let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let end = 40usize.checked_add(payload_len)?;
        if end > bytes.len() {
            return None;
        }

        let src_addr = address_from_bytes(&bytes[8..24])?;
        let dst_addr = address_from_bytes(&bytes[24..40])?;
        let next_header = bytes[6];
        let (src_port, dst_port) = match next_header {
            6 | 17 if payload_len >= 4 => (
                Some(u16::from_be_bytes([bytes[40], bytes[41]])),
                Some(u16::from_be_bytes([bytes[42], bytes[43]])),
            ),
            // ICMPv6 Echo uses the identifier as a stable flow key.  Other
            // ICMPv6 messages remain address-matched and carry no ports.
            58 if payload_len >= 6 && (bytes[40] == 128 || bytes[40] == 129) => (
                Some(u16::from_be_bytes([bytes[44], bytes[45]])),
                None,
            ),
            _ => (None, None),
        };

        Some(Self {
            src_addr,
            dst_addr,
            next_header,
            src_port,
            dst_port,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Ipv6NatConnection {
    protocol: u8,
    original_src: Ipv6Address,
    original_dst: Ipv6Address,
    original_src_port: Option<u16>,
    original_dst_port: Option<u16>,
    translated_src: Ipv6Address,
    translated_dst: Ipv6Address,
    translated_src_port: Option<u16>,
    translated_dst_port: Option<u16>,
    packets: u64,
    bytes: u64,
}

impl Ipv6NatConnection {
    const fn new(tuple: Ipv6Tuple) -> Self {
        Self {
            protocol: tuple.next_header,
            original_src: tuple.src_addr,
            original_dst: tuple.dst_addr,
            original_src_port: tuple.src_port,
            original_dst_port: tuple.dst_port,
            translated_src: tuple.src_addr,
            translated_dst: tuple.dst_addr,
            translated_src_port: tuple.src_port,
            translated_dst_port: tuple.dst_port,
            packets: 0,
            bytes: 0,
        }
    }

    fn matches_reverse(self, tuple: Ipv6Tuple) -> bool {
        if self.protocol != tuple.next_header
            || self.translated_dst != tuple.src_addr
            || self.translated_src != tuple.dst_addr
        {
            return false;
        }
        if self.protocol == 58 {
            // Echo request and reply carry the same identifier in the
            // request's source-port slot; there is no destination port.
            return self.translated_src_port == tuple.src_port;
        }
        self.translated_dst_port == tuple.src_port
            && self.translated_src_port == tuple.dst_port
    }

    fn matches_translated_forward(self, tuple: Ipv6Tuple) -> bool {
        self.protocol == tuple.next_header
            && self.translated_src == tuple.src_addr
            && self.translated_dst == tuple.dst_addr
            && self.translated_src_port == tuple.src_port
            && self.translated_dst_port == tuple.dst_port
    }

    fn record(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }
}

#[derive(Debug)]
struct MutableIpv6Nat {
    rules: [Option<Ipv6NatRule>; MAX_IPV6_NAT_RULES],
    rule_len: usize,
    connections: [Option<Ipv6NatConnection>; MAX_IPV6_NAT_CONNECTIONS],
}

impl MutableIpv6Nat {
    const fn new() -> Self {
        Self {
            rules: [None; MAX_IPV6_NAT_RULES],
            rule_len: 0,
            connections: [None; MAX_IPV6_NAT_CONNECTIONS],
        }
    }

    fn append_rule(&mut self, rule: Ipv6NatRule) -> bool {
        if self.rule_len == MAX_IPV6_NAT_RULES {
            return false;
        }
        self.rules[self.rule_len] = Some(rule);
        self.rule_len += 1;
        true
    }

    fn flush(&mut self, chain: Option<Ipv6NatRuleChain>) {
        let mut kept = 0;
        for index in 0..self.rule_len {
            let Some(rule) = self.rules[index] else {
                continue;
            };
            if chain.is_some_and(|wanted| wanted == rule.chain) {
                continue;
            }
            self.rules[kept] = Some(rule);
            kept += 1;
        }
        for slot in &mut self.rules[kept..] {
            *slot = None;
        }
        self.rule_len = kept;
        // A rule flush invalidates mappings that could otherwise rewrite a
        // later packet using a policy which no longer exists.
        self.connections.fill(None);
    }

    fn zero(&mut self) {
        for rule in &mut self.rules[..self.rule_len] {
            if let Some(rule) = rule.as_mut() {
                rule.packets = 0;
                rule.bytes = 0;
            }
        }
        for connection in self.connections.iter_mut().flatten() {
            connection.packets = 0;
            connection.bytes = 0;
        }
    }

    fn apply_prerouting(&mut self, packet: &mut [u8]) -> bool {
        let Some(tuple) = Ipv6Tuple::parse(packet) else {
            return false;
        };
        if !supports_address_rewrite(tuple.next_header) {
            return false;
        }

        if let Some(index) = self
            .connections
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|connection| connection.matches_reverse(tuple))
            })
        {
            let connection = self.connections[index].unwrap();
            let changed = crate::forwarding::rewrite_ipv6_addresses(
                packet,
                (connection.translated_dst != connection.original_dst)
                    .then_some(connection.original_dst),
                (connection.translated_src != connection.original_src)
                    .then_some(connection.original_src),
            );
            if let Some(connection) = self.connections[index].as_mut() {
                connection.record(packet.len());
            }
            return changed;
        }

        let Some(index) = self.find_rule(Ipv6NatRuleChain::PreRouting, tuple) else {
            return false;
        };
        let rule = self.rules[index].unwrap();
        let mut connection = Ipv6NatConnection::new(tuple);
        let mut source = None;
        let mut destination = None;
        match rule.target {
            Ipv6NatRuleTarget::Dnat => {
                let Some(address) = rule.to_addr else {
                    return false;
                };
                connection.translated_dst = address;
                destination = Some(address);
            }
            Ipv6NatRuleTarget::Snat => {
                let Some(address) = rule.to_addr else {
                    return false;
                };
                connection.translated_src = address;
                source = Some(address);
            }
            Ipv6NatRuleTarget::Masquerade => return false,
        }

        if !self.install_connection(connection) {
            return false;
        }
        self.rules[index].as_mut().unwrap().record(packet.len());
        crate::forwarding::rewrite_ipv6_addresses(packet, source, destination)
    }

    fn apply_postrouting(
        &mut self,
        packet: &mut ForwardedIpv6Packet,
        masquerade_addr: Option<Ipv6Address>,
    ) -> bool {
        let Some(tuple) = Ipv6Tuple::parse(packet.bytes()) else {
            return false;
        };
        if !supports_address_rewrite(tuple.next_header) {
            return false;
        }

        let existing = self
            .connections
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|connection| connection.matches_translated_forward(tuple))
            });

        let Some(index) = self.find_rule(Ipv6NatRuleChain::PostRouting, tuple) else {
            return false;
        };
        let rule = self.rules[index].unwrap();
        let translated_source = match rule.target {
            Ipv6NatRuleTarget::Dnat => return false,
            Ipv6NatRuleTarget::Snat => rule.to_addr,
            Ipv6NatRuleTarget::Masquerade => masquerade_addr,
        };
        let Some(translated_source) = translated_source else {
            return false;
        };

        if let Some(connection_index) = existing {
            if let Some(connection) = self.connections[connection_index].as_mut() {
                connection.translated_src = translated_source;
                connection.translated_src_port = tuple.src_port;
                connection.record(packet.buffer_len());
            }
        } else {
            let mut connection = Ipv6NatConnection::new(tuple);
            connection.translated_src = translated_source;
            connection.translated_src_port = tuple.src_port;
            if !self.install_connection(connection) {
                return false;
            }
        }

        self.rules[index].as_mut().unwrap().record(packet.buffer_len());
        packet.rewrite_source_address(translated_source)
    }

    fn find_rule(&self, chain: Ipv6NatRuleChain, tuple: Ipv6Tuple) -> Option<usize> {
        self.rules[..self.rule_len]
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|rule| rule.matches(chain, tuple)))
    }

    fn install_connection(&mut self, connection: Ipv6NatConnection) -> bool {
        if let Some(existing) = self.connections.iter_mut().find(|slot| {
            slot.as_ref().is_some_and(|current| {
                current.protocol == connection.protocol
                    && current.original_src == connection.original_src
                    && current.original_dst == connection.original_dst
                    && current.original_src_port == connection.original_src_port
                    && current.original_dst_port == connection.original_dst_port
            })
        }) {
            let counters = existing.as_ref().copied().unwrap();
            let mut replacement = connection;
            replacement.packets = counters.packets;
            replacement.bytes = counters.bytes;
            *existing = Some(replacement);
            return true;
        }

        if let Some(slot) = self.connections.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(connection);
            true
        } else {
            false
        }
    }
}

/// Adds one IPv6 NAT66 rule.
pub fn append_nat_rule(
    chain: Ipv6NatRuleChain,
    protocol: Ipv6RuleProtocol,
    src_addr: Option<Ipv6Address>,
    dst_addr: Option<Ipv6Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    target: Ipv6NatRuleTarget,
    to_addr: Option<Ipv6Address>,
) -> bool {
    IPV6_NAT.lock().append_rule(Ipv6NatRule::new(
        chain, protocol, src_addr, dst_addr, src_port, dst_port, target, to_addr,
    ))
}

/// Applies PREROUTING NAT66 and reverse conntrack mapping to an ingress frame.
pub fn apply_prerouting(packet: &mut [u8]) -> bool {
    IPV6_NAT.lock().apply_prerouting(packet)
}

/// Applies POSTROUTING NAT66 after the IPv6 egress interface is selected.
pub fn apply_postrouting(
    packet: &mut ForwardedIpv6Packet,
    masquerade_addr: Option<Ipv6Address>,
) -> bool {
    IPV6_NAT
        .lock()
        .apply_postrouting(packet, masquerade_addr)
}

/// Flushes one IPv6 nat chain, or the complete table when `None` is supplied.
pub fn flush_rules(chain: Option<Ipv6NatRuleChain>) {
    IPV6_NAT.lock().flush(chain);
}

/// Clears IPv6 NAT rule and conntrack counters.
pub fn zero_counters() {
    IPV6_NAT.lock().zero();
}

/// Renders the IPv6 NAT rules and bounded conntrack table in procfs format.
pub fn write_snapshot(writer: &mut impl core::fmt::Write) -> core::fmt::Result {
    let nat = IPV6_NAT.lock();
    writeln!(writer, "table nat6")?;
    for chain in [Ipv6NatRuleChain::PreRouting, Ipv6NatRuleChain::PostRouting] {
        writeln!(writer, "chain6nat {} policy ACCEPT", FormatChain(chain))?;
        for (index, rule) in nat.rules[..nat.rule_len]
            .iter()
            .flatten()
            .filter(|rule| rule.chain == chain)
            .enumerate()
        {
            writeln!(
                writer,
                "  rule6nat {} pkts {} bytes {} proto {} src {} dst {} sport {:?} dport {:?} target {} to {}",
                index,
                rule.packets,
                rule.bytes,
                FormatProtocol(rule.protocol),
                FormatAddress(rule.src_addr),
                FormatAddress(rule.dst_addr),
                rule.src_port,
                rule.dst_port,
                FormatTarget(rule.target),
                FormatAddress(rule.to_addr),
            )?;
        }
        writeln!(writer, "state stage12-{}-rule-count {}", FormatChain(chain), nat.rules[..nat.rule_len].iter().flatten().filter(|rule| rule.chain == chain).count())?;
    }
    let connection_count = nat.connections.iter().filter(|slot| slot.is_some()).count();
    writeln!(writer, "state stage12-ipv6-nat-connection-count {}", connection_count)
}

fn address_from_bytes(bytes: &[u8]) -> Option<Ipv6Address> {
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

const fn supports_address_rewrite(next_header: u8) -> bool {
    matches!(next_header, 6 | 17 | 58)
}

struct FormatChain(Ipv6NatRuleChain);

impl core::fmt::Display for FormatChain {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self.0 {
            Ipv6NatRuleChain::PreRouting => "PREROUTING",
            Ipv6NatRuleChain::PostRouting => "POSTROUTING",
        })
    }
}

struct FormatTarget(Ipv6NatRuleTarget);

impl core::fmt::Display for FormatTarget {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self.0 {
            Ipv6NatRuleTarget::Dnat => "DNAT",
            Ipv6NatRuleTarget::Masquerade => "MASQUERADE",
            Ipv6NatRuleTarget::Snat => "SNAT",
        })
    }
}

struct FormatProtocol(Ipv6RuleProtocol);

impl core::fmt::Display for FormatProtocol {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self.0 {
            Ipv6RuleProtocol::Any => "all",
            Ipv6RuleProtocol::Icmpv6 => "ipv6-icmp",
            Ipv6RuleProtocol::Tcp => "tcp",
            Ipv6RuleProtocol::Udp => "udp",
        })
    }
}

struct FormatAddress(Option<Ipv6Address>);

impl core::fmt::Display for FormatAddress {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Some(address) = self.0 else {
            return formatter.write_str("any");
        };
        let octets = address.octets();
        for index in 0..8 {
            if index != 0 {
                formatter.write_str(":")?;
            }
            write!(formatter, "{:x}", u16::from_be_bytes([octets[index * 2], octets[index * 2 + 1]]))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_connection_matches_translated_tuple() {
        let source = Ipv6Address::new(0xfd00, 0, 0, 2, 0, 0, 0, 2);
        let destination = Ipv6Address::new(0xfd00, 0, 0, 3, 0, 0, 0, 2);
        let tuple = Ipv6Tuple {
            src_addr: source,
            dst_addr: destination,
            next_header: 58,
            src_port: Some(7),
            dst_port: None,
        };
        let mut connection = Ipv6NatConnection::new(tuple);
        connection.translated_src = Ipv6Address::new(0xfd00, 0, 0, 3, 0, 0, 0, 15);
        assert!(connection.matches_reverse(Ipv6Tuple {
            src_addr: destination,
            dst_addr: connection.translated_src,
            next_header: 58,
            src_port: Some(7),
            dst_port: None,
        }));
    }
}
