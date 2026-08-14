// SPDX-License-Identifier: MPL-2.0

use aster_softirq::BottomHalfDisabled;
use ostd::{
    sync::SpinLock,
    timer::Jiffies,
};
use smoltcp::wire::{Icmpv4Repr, Ipv4Address, Ipv4Repr, TcpRepr, UdpRepr};

use super::{
    chain::Chain,
    hook::{HookPoint, Ipv4PacketContext, Verdict},
    rule::Action,
};

const MAX_FILTER_RULES: usize = 64;
const MAX_NAT_RULES: usize = 8;
const MAX_NAT_ICMP_CONNECTIONS: usize = 32;
const MAX_NAT_TRANSPORT_CONNECTIONS: usize = 64;
const NAT_EPHEMERAL_PORT_FIRST: u16 = 40_000;
const NAT_EPHEMERAL_PORT_LAST: u16 = 59_999;
const IPV4_MIN_HEADER_LEN: usize = 20;
const NAT_ICMP_TIMEOUT_MILLIS: u64 = 30_000;
const NAT_UDP_TIMEOUT_MILLIS: u64 = 60_000;
const NAT_TCP_NEW_TIMEOUT_MILLIS: u64 = 30_000;
const NAT_TCP_ESTABLISHED_TIMEOUT_MILLIS: u64 = 300_000;

static FILTER_RULES: [SpinLock<MutableFilterRules, BottomHalfDisabled>; 5] = [
    SpinLock::new(MutableFilterRules::new()),
    SpinLock::new(MutableFilterRules::new()),
    SpinLock::new(MutableFilterRules::new()),
    SpinLock::new(MutableFilterRules::new()),
    SpinLock::new(MutableFilterRules::new()),
];
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
struct MutableFilterRules {
    rules: [Option<OutputRule>; MAX_FILTER_RULES],
    len: usize,
    policy: Action,
}

#[derive(Debug)]
struct MutableNatRules {
    rules: [Option<NatRule>; MAX_NAT_RULES],
    len: usize,
    icmp_connections: [Option<NatIcmpConnection>; MAX_NAT_ICMP_CONNECTIONS],
    transport_connections: [Option<NatTransportConnection>; MAX_NAT_TRANSPORT_CONNECTIONS],
    next_ephemeral_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OutputRule {
    protocol: OutputRuleProtocol,
    icmp_echo_ident: Option<u16>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    conntrack_state: Option<ConntrackState>,
    action: Action,
    packets: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// 有界、仅地址的 ICMP NAT 映射。
///
/// 该实现有意比 Linux conntrack 更窄：它为 Echo 流量提供首个可用的有状态 NAT 路径，
/// 但不宣称 TCP/UDP 端口和生命周期跟踪已经完整。`original_*` 表示 NAT 前收到的
/// 数据包，`translated_*` 表示经 PREROUTING 和 POSTROUTING 转换后发出的数据包。
#[derive(Clone, Copy, Debug)]
struct NatIcmpConnection {
    original_src: Ipv4Address,
    original_dst: Ipv4Address,
    translated_src: Ipv4Address,
    translated_dst: Ipv4Address,
    last_seen_millis: u64,
}

/// 有界的有状态 TCP 或 UDP NAT 映射。
///
/// tuple 有意保存在固定大小的表中：转发路径不能分配内存；只要活动映射仍占用相同出口
/// tuple，就不会复用转换后的源端口。阶段 6 使用按协议设置的有界超时回收空闲槽位，
/// 因此耗尽行为保持确定性。
#[derive(Clone, Copy, Debug)]
struct NatTransportConnection {
    protocol: OutputRuleProtocol,
    original_src: Ipv4Address,
    original_dst: Ipv4Address,
    original_src_port: u16,
    original_dst_port: u16,
    translated_src: Ipv4Address,
    translated_dst: Ipv4Address,
    translated_src_port: u16,
    translated_dst_port: u16,
    state: ConntrackState,
    last_seen_millis: u64,
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

    fn matches_prerouting_transport(
        self,
        protocol: OutputRuleProtocol,
        ipv4_repr: &Ipv4Repr,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        if self.chain != NatRuleChain::PreRouting || !self.matches_common_ipv4(ipv4_repr) {
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

        self.target == NatRuleTarget::Dnat && self.to_addr.is_some()
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

    fn matches_prerouting_icmp(self, ipv4_repr: &Ipv4Repr) -> bool {
        if self.chain != NatRuleChain::PreRouting || !self.matches_common_ipv4(ipv4_repr) {
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
            && matches!(self.target, NatRuleTarget::Dnat)
            && self.to_addr.is_some()
    }

    fn record_match(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }

    fn same_configuration(self, other: Self) -> bool {
        self.chain == other.chain
            && self.protocol == other.protocol
            && self.src_addr == other.src_addr
            && self.dst_addr == other.dst_addr
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
            && self.target == other.target
            && self.to_addr == other.to_addr
            && self.to_port == other.to_port
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
            conntrack_state: None,
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
        conntrack_state: Option<ConntrackState>,
        action: Action,
    ) -> Self {
        Self {
            protocol,
            icmp_echo_ident: None,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            conntrack_state,
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
        conntrack_state: ConntrackState,
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

        if self
            .conntrack_state
            .is_some_and(|expected| expected != conntrack_state)
        {
            return false;
        }

        true
    }

    fn same_configuration(self, other: Self) -> bool {
        self.protocol == other.protocol
            && self.icmp_echo_ident == other.icmp_echo_ident
            && self.src_addr == other.src_addr
            && self.dst_addr == other.dst_addr
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
            && self.conntrack_state == other.conntrack_state
            && self.action == other.action
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
            icmp_connections: [None; MAX_NAT_ICMP_CONNECTIONS],
            transport_connections: [None; MAX_NAT_TRANSPORT_CONNECTIONS],
            next_ephemeral_port: NAT_EPHEMERAL_PORT_FIRST,
        }
    }

    fn reap_expired_connections(&mut self, now_millis: u64) {
        for slot in &mut self.icmp_connections {
            if slot.is_some_and(|connection| {
                now_millis.saturating_sub(connection.last_seen_millis) >= NAT_ICMP_TIMEOUT_MILLIS
            }) {
                *slot = None;
            }
        }

        for slot in &mut self.transport_connections {
            if slot.is_some_and(|connection| {
                now_millis.saturating_sub(connection.last_seen_millis)
                    >= transport_timeout_millis(connection)
            }) {
                *slot = None;
            }
        }
    }

    fn conntrack_state_for_transport(
        &mut self,
        protocol: OutputRuleProtocol,
        ipv4_repr: &Ipv4Repr,
        src_port: u16,
        dst_port: u16,
    ) -> ConntrackState {
        let now_millis = netfilter_now_millis();
        self.reap_expired_connections(now_millis);

        let Some(connection) = self.transport_connections.iter_mut().flatten().find(|connection| {
            connection.protocol == protocol
                && transport_tuple_matches(connection, ipv4_repr, src_port, dst_port)
        }) else {
            return ConntrackState::New;
        };

        connection.last_seen_millis = now_millis;
        connection.state
    }

    fn append_rule(&mut self, rule: NatRule) -> bool {
        if self.len == MAX_NAT_RULES {
            return false;
        }

        self.rules[self.len] = Some(rule);
        self.len += 1;
        true
    }

    /// 在一条 NAT 链中按从零开始的位置插入规则。
    ///
    /// PREROUTING 和 POSTROUTING 共享固定后备数组，但位置遵循 iptables 的链内编号。
    fn insert_rule(&mut self, chain: NatRuleChain, index: usize, rule: NatRule) -> bool {
        if self.len == MAX_NAT_RULES {
            return false;
        }

        let mut chain_index = 0;
        let mut insert_at = self.len;
        for current_index in 0..self.len {
            let Some(current_rule) = self.rules[current_index] else {
                continue;
            };
            if current_rule.chain != chain {
                continue;
            }
            if chain_index == index {
                insert_at = current_index;
                break;
            }
            chain_index += 1;
        }
        if index != chain_index && insert_at == self.len {
            return false;
        }

        for current_index in (insert_at..self.len).rev() {
            self.rules[current_index + 1] = self.rules[current_index];
        }
        self.rules[insert_at] = Some(rule);
        self.len += 1;
        self.reset_connections();
        true
    }

    fn check_rule(&self, rule: NatRule) -> bool {
        self.rules[..self.len]
            .iter()
            .flatten()
            .any(|current| current.same_configuration(rule))
    }

    fn replace_rule(&mut self, chain: NatRuleChain, index: usize, rule: NatRule) -> bool {
        let mut chain_index = 0;
        for current_index in 0..self.len {
            let Some(current_rule) = self.rules[current_index] else {
                continue;
            };
            if current_rule.chain != chain {
                continue;
            }
            if chain_index == index {
                self.rules[current_index] = Some(rule);
                self.reset_connections();
                return true;
            }
            chain_index += 1;
        }

        false
    }

    /// 删除一条 NAT 链中从零开始编号的规则位置。
    fn delete_rule(&mut self, chain: NatRuleChain, index: usize) -> bool {
        let mut chain_index = 0;
        let mut delete_at = None;
        for current_index in 0..self.len {
            let Some(current_rule) = self.rules[current_index] else {
                continue;
            };
            if current_rule.chain != chain {
                continue;
            }
            if chain_index == index {
                delete_at = Some(current_index);
                break;
            }
            chain_index += 1;
        }
        let Some(delete_at) = delete_at else {
            return false;
        };

        for current_index in delete_at..self.len - 1 {
            self.rules[current_index] = self.rules[current_index + 1];
        }
        self.len -= 1;
        self.rules[self.len] = None;
        self.reset_connections();
        true
    }

    fn zero_counters(&mut self, chain: Option<NatRuleChain>) {
        for rule in self.rules[..self.len].iter_mut().flatten() {
            if chain.is_none() || chain == Some(rule.chain) {
                rule.packets = 0;
                rule.bytes = 0;
            }
        }
    }

    fn reset_connections(&mut self) {
        for connection in &mut self.icmp_connections {
            *connection = None;
        }
        for connection in &mut self.transport_connections {
            *connection = None;
        }
        self.next_ephemeral_port = NAT_EPHEMERAL_PORT_FIRST;
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

        // 清空规则时也要重置 NAT 状态。保留由已删除规则创建的映射会让控制面行为
        // 出乎预期，还可能使回复流量经过已废弃的转换。
        for connection in &mut self.icmp_connections {
            *connection = None;
        }
        for connection in &mut self.transport_connections {
            *connection = None;
        }
        self.next_ephemeral_port = NAT_EPHEMERAL_PORT_FIRST;
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

    fn rewrite_forwarded_icmp_prerouting(&mut self, ipv4_repr: &mut Ipv4Repr) {
        if ipv4_repr.next_header != smoltcp::wire::IpProtocol::Icmp {
            return;
        }

        // 反向转换优先于新的 DNAT 规则。发往 SNAT/MASQUERADE 地址的回复以路由器
        // 自身为目标，因此该处理发生在调用方选择本地投递之前。
        if let Some(connection) = self.icmp_connections.iter().flatten().find(|connection| {
            connection.translated_dst == ipv4_repr.src_addr
                && connection.translated_src == ipv4_repr.dst_addr
        }) {
            ipv4_repr.src_addr = connection.original_dst;
            ipv4_repr.dst_addr = connection.original_src;
            return;
        }

        let original_src = ipv4_repr.src_addr;
        let original_dst = ipv4_repr.dst_addr;
        let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(ipv4_repr.payload_len);
        let translated_dst = self.rules[..self.len]
            .iter_mut()
            .filter_map(Option::as_mut)
            .find(|rule| rule.matches_prerouting_icmp(ipv4_repr))
            .and_then(|rule| {
                rule.record_match(packet_len);
                rule.to_addr
            });
        let Some(translated_dst) = translated_dst else {
            return;
        };

        ipv4_repr.dst_addr = translated_dst;
        self.upsert_icmp_connection(NatIcmpConnection {
            original_src,
            original_dst,
            translated_src: original_src,
            translated_dst,
            last_seen_millis: netfilter_now_millis(),
        });
    }

    fn rewrite_forwarded_icmp_postrouting(
        &mut self,
        ipv4_repr: &mut Ipv4Repr,
        masquerade_addr: Option<Ipv4Address>,
    ) {
        if ipv4_repr.next_header != smoltcp::wire::IpProtocol::Icmp {
            return;
        }

        let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(ipv4_repr.payload_len);
        let translated_src = self.rules[..self.len]
            .iter_mut()
            .filter_map(Option::as_mut)
            .find(|rule| rule.matches_postrouting_icmp(ipv4_repr))
            .and_then(|rule| {
                let translated_src = match rule.target {
                    NatRuleTarget::Masquerade => masquerade_addr,
                    NatRuleTarget::Snat => rule.to_addr,
                    NatRuleTarget::Dnat => None,
                };
                translated_src.inspect(|_| rule.record_match(packet_len))
            });
        let Some(translated_src) = translated_src else {
            return;
        };

        let translated_dst = ipv4_repr.dst_addr;
        let connection = self
            .icmp_connections
            .iter()
            .flatten()
            .find(|connection| {
                connection.translated_src == ipv4_repr.src_addr
                    && connection.translated_dst == translated_dst
            })
            .copied()
            .unwrap_or(NatIcmpConnection {
                original_src: ipv4_repr.src_addr,
                original_dst: translated_dst,
                translated_src: ipv4_repr.src_addr,
                translated_dst,
                last_seen_millis: netfilter_now_millis(),
            });

        ipv4_repr.src_addr = translated_src;
        self.upsert_icmp_connection(NatIcmpConnection {
            translated_src,
            translated_dst,
            last_seen_millis: netfilter_now_millis(),
            ..connection
        });
    }

    fn rewrite_forwarded_prerouting(&mut self, ipv4_repr: &mut Ipv4Repr, payload: &mut [u8]) {
        self.reap_expired_connections(netfilter_now_millis());
        let Some(protocol) = transport_protocol(ipv4_repr) else {
            self.rewrite_forwarded_icmp_prerouting(ipv4_repr);
            return;
        };
        let Some((src_port, dst_port)) = transport_ports(payload) else {
            return;
        };

        // 回复流量包含转换后的目标 tuple。在路由查询前恢复地址和端口，
        // 使发往路由器地址的回复得到转发，而不会被误认为本地流量。
        if let Some(connection) = self
            .transport_connections
            .iter_mut()
            .flatten()
            .find(|connection| {
                connection.protocol == protocol
                    && connection.translated_dst == ipv4_repr.src_addr
                    && connection.translated_src == ipv4_repr.dst_addr
                    && connection.translated_dst_port == src_port
                    && connection.translated_src_port == dst_port
            })
        {
            connection.state = ConntrackState::Established;
            connection.last_seen_millis = netfilter_now_millis();
            apply_transport_translation(
                protocol,
                ipv4_repr,
                payload,
                connection.original_dst,
                connection.original_src,
                connection.original_dst_port,
                connection.original_src_port,
            );
            return;
        }

        // 原始方向上的每个数据包都复用 DNAT 映射。
        // SNAT 映射有意推迟到 POSTROUTING，因为 MASQUERADE 地址由选定的出口接口提供。
        if let Some(connection) = self
            .transport_connections
            .iter_mut()
            .flatten()
            .find(|connection| {
                connection.protocol == protocol
                    && connection.original_src == ipv4_repr.src_addr
                    && connection.original_dst == ipv4_repr.dst_addr
                    && connection.original_src_port == src_port
                    && connection.original_dst_port == dst_port
                    && (connection.original_dst != connection.translated_dst
                        || connection.original_dst_port != connection.translated_dst_port)
            })
        {
            connection.last_seen_millis = netfilter_now_millis();
            apply_transport_translation(
                protocol,
                ipv4_repr,
                payload,
                connection.translated_src,
                connection.translated_dst,
                connection.translated_src_port,
                connection.translated_dst_port,
            );
            return;
        }

        let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(ipv4_repr.payload_len);
        let Some(rule_index) = (0..self.len).find(|index| {
            self.rules[*index].is_some_and(|rule| {
                rule.matches_prerouting_transport(protocol, ipv4_repr, src_port, dst_port)
            })
        }) else {
            return;
        };
        let Some(rule) = self.rules[rule_index] else {
            return;
        };
        let Some(translated_dst) = rule.to_addr else {
            return;
        };
        if !self.transport_connections.iter().any(Option::is_none) {
            return;
        }
        let translated_dst_port = rule.to_port.unwrap_or(dst_port);
        self.rules[rule_index]
            .as_mut()
            .expect("matched NAT rule remains installed")
            .record_match(packet_len);

        let original_src = ipv4_repr.src_addr;
        let original_dst = ipv4_repr.dst_addr;
        apply_transport_translation(
            protocol,
            ipv4_repr,
            payload,
            original_src,
            translated_dst,
            src_port,
            translated_dst_port,
        );
        self.upsert_transport_connection(NatTransportConnection {
            protocol,
            original_src,
            original_dst,
            original_src_port: src_port,
            original_dst_port: dst_port,
            translated_src: original_src,
            translated_dst,
            translated_src_port: src_port,
            translated_dst_port,
            state: ConntrackState::New,
            last_seen_millis: netfilter_now_millis(),
        });
    }

    fn rewrite_forwarded_postrouting(
        &mut self,
        ipv4_repr: &mut Ipv4Repr,
        payload: &mut [u8],
        masquerade_addr: Option<Ipv4Address>,
    ) {
        self.reap_expired_connections(netfilter_now_millis());
        let Some(protocol) = transport_protocol(ipv4_repr) else {
            self.rewrite_forwarded_icmp_postrouting(ipv4_repr, masquerade_addr);
            return;
        };
        let Some((src_port, dst_port)) = transport_ports(payload) else {
            return;
        };

        // 重复的原始方向数据包复用已分配的 NAT tuple。
        // 这样可以覆盖 TCP 重传和 UDP 数据报，而不改变其转换后的源端口。
        if let Some(connection) = self
            .transport_connections
            .iter_mut()
            .flatten()
            .find(|connection| {
                connection.protocol == protocol
                    && connection.original_src == ipv4_repr.src_addr
                    && connection.original_dst == ipv4_repr.dst_addr
                    && connection.original_src_port == src_port
                    && connection.original_dst_port == dst_port
            })
        {
            connection.last_seen_millis = netfilter_now_millis();
            apply_transport_translation(
                protocol,
                ipv4_repr,
                payload,
                connection.translated_src,
                connection.translated_dst,
                connection.translated_src_port,
                connection.translated_dst_port,
            );
            return;
        }

        // DNAT 流已经在 PREROUTING 完成转换，除非后续阶段明确支持成对的
        // DNAT+SNAT 规则，否则无需进一步修改。
        if self.transport_connections.iter().flatten().any(|connection| {
            connection.protocol == protocol
                && connection.translated_src == ipv4_repr.src_addr
                && connection.translated_dst == ipv4_repr.dst_addr
                && connection.translated_src_port == src_port
                && connection.translated_dst_port == dst_port
        }) {
            return;
        }

        let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(ipv4_repr.payload_len);
        let Some(rule_index) = (0..self.len).find(|index| {
            self.rules[*index].is_some_and(|rule| {
                rule.matches_postrouting_transport(protocol, ipv4_repr, src_port, dst_port)
            })
        }) else {
            return;
        };
        let Some(rule) = self.rules[rule_index] else {
            return;
        };
        let translated_src = match rule.target {
            NatRuleTarget::Masquerade => masquerade_addr,
            NatRuleTarget::Snat => rule.to_addr,
            NatRuleTarget::Dnat => None,
        };
        let Some(translated_src) = translated_src else {
            return;
        };
        if !self.transport_connections.iter().any(Option::is_none) {
            return;
        }

        let translated_src_port = match rule.to_port {
            Some(port) if self.translated_tuple_available(protocol, translated_src, port, ipv4_repr.dst_addr, dst_port) => port,
            Some(_) => return,
            None => match self.allocate_translated_port(
                protocol,
                translated_src,
                ipv4_repr.dst_addr,
                dst_port,
            ) {
                Some(port) => port,
                None => return,
            },
        };
        self.rules[rule_index]
            .as_mut()
            .expect("matched NAT rule remains installed")
            .record_match(packet_len);

        let original_src = ipv4_repr.src_addr;
        let original_dst = ipv4_repr.dst_addr;
        apply_transport_translation(
            protocol,
            ipv4_repr,
            payload,
            translated_src,
            original_dst,
            translated_src_port,
            dst_port,
        );
        self.upsert_transport_connection(NatTransportConnection {
            protocol,
            original_src,
            original_dst,
            original_src_port: src_port,
            original_dst_port: dst_port,
            translated_src,
            translated_dst: original_dst,
            translated_src_port,
            translated_dst_port: dst_port,
            state: ConntrackState::New,
            last_seen_millis: netfilter_now_millis(),
        });
    }

    fn translated_tuple_available(
        &self,
        protocol: OutputRuleProtocol,
        src_addr: Ipv4Address,
        src_port: u16,
        dst_addr: Ipv4Address,
        dst_port: u16,
    ) -> bool {
        !self.transport_connections.iter().flatten().any(|connection| {
            connection.protocol == protocol
                && connection.translated_src == src_addr
                && connection.translated_src_port == src_port
                && connection.translated_dst == dst_addr
                && connection.translated_dst_port == dst_port
        })
    }

    fn allocate_translated_port(
        &mut self,
        protocol: OutputRuleProtocol,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        dst_port: u16,
    ) -> Option<u16> {
        let port_count = usize::from(NAT_EPHEMERAL_PORT_LAST - NAT_EPHEMERAL_PORT_FIRST + 1);
        for _ in 0..port_count {
            let candidate = self.next_ephemeral_port;
            self.next_ephemeral_port = if candidate == NAT_EPHEMERAL_PORT_LAST {
                NAT_EPHEMERAL_PORT_FIRST
            } else {
                candidate + 1
            };
            if self.translated_tuple_available(protocol, src_addr, candidate, dst_addr, dst_port) {
                return Some(candidate);
            }
        }
        None
    }

    fn upsert_icmp_connection(&mut self, connection: NatIcmpConnection) {
        if let Some(slot) = self.icmp_connections.iter_mut().find(|slot| {
            slot.as_ref().is_some_and(|existing| {
                existing.original_src == connection.original_src
                    && existing.original_dst == connection.original_dst
            })
        }) {
            *slot = Some(connection);
            return;
        }

        if let Some(slot) = self.icmp_connections.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(connection);
        }
    }

    fn upsert_transport_connection(&mut self, connection: NatTransportConnection) {
        if let Some(slot) = self.transport_connections.iter_mut().find(|slot| {
            slot.as_ref().is_some_and(|existing| {
                existing.protocol == connection.protocol
                    && existing.original_src == connection.original_src
                    && existing.original_dst == connection.original_dst
                    && existing.original_src_port == connection.original_src_port
                    && existing.original_dst_port == connection.original_dst_port
            })
        }) {
            *slot = Some(connection);
            return;
        }

        if let Some(slot) = self.transport_connections.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(connection);
        }
    }
}

fn transport_protocol(ipv4_repr: &Ipv4Repr) -> Option<OutputRuleProtocol> {
    match ipv4_repr.next_header {
        smoltcp::wire::IpProtocol::Tcp => Some(OutputRuleProtocol::Tcp),
        smoltcp::wire::IpProtocol::Udp => Some(OutputRuleProtocol::Udp),
        _ => None,
    }
}

fn transport_ports(payload: &[u8]) -> Option<(u16, u16)> {
    (payload.len() >= 4).then(|| {
        (
            u16::from_be_bytes([payload[0], payload[1]]),
            u16::from_be_bytes([payload[2], payload[3]]),
        )
    })
}

fn netfilter_now_millis() -> u64 {
    Jiffies::elapsed().as_duration().as_millis() as u64
}

fn transport_timeout_millis(connection: NatTransportConnection) -> u64 {
    match (connection.protocol, connection.state) {
        (OutputRuleProtocol::Tcp, ConntrackState::New) => NAT_TCP_NEW_TIMEOUT_MILLIS,
        (OutputRuleProtocol::Tcp, ConntrackState::Established) => {
            NAT_TCP_ESTABLISHED_TIMEOUT_MILLIS
        }
        (OutputRuleProtocol::Udp, _) => NAT_UDP_TIMEOUT_MILLIS,
        (OutputRuleProtocol::Icmp, _) => 0,
    }
}

fn transport_tuple_matches(
    connection: &NatTransportConnection,
    ipv4_repr: &Ipv4Repr,
    src_port: u16,
    dst_port: u16,
) -> bool {
    (connection.original_src == ipv4_repr.src_addr
        && connection.original_dst == ipv4_repr.dst_addr
        && connection.original_src_port == src_port
        && connection.original_dst_port == dst_port)
        || (connection.translated_src == ipv4_repr.src_addr
            && connection.translated_dst == ipv4_repr.dst_addr
            && connection.translated_src_port == src_port
            && connection.translated_dst_port == dst_port)
        || (connection.original_dst == ipv4_repr.src_addr
            && connection.original_src == ipv4_repr.dst_addr
            && connection.original_dst_port == src_port
            && connection.original_src_port == dst_port)
        || (connection.translated_dst == ipv4_repr.src_addr
            && connection.translated_src == ipv4_repr.dst_addr
            && connection.translated_dst_port == src_port
            && connection.translated_src_port == dst_port)
}

fn conntrack_state_for_transport(
    protocol: OutputRuleProtocol,
    ipv4_repr: &Ipv4Repr,
    src_port: u16,
    dst_port: u16,
) -> ConntrackState {
    NAT_RULES
        .lock()
        .conntrack_state_for_transport(protocol, ipv4_repr, src_port, dst_port)
}

fn apply_transport_translation(
    protocol: OutputRuleProtocol,
    ipv4_repr: &mut Ipv4Repr,
    payload: &mut [u8],
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    src_port: u16,
    dst_port: u16,
) {
    if payload.len() < transport_header_len(protocol) {
        return;
    }

    ipv4_repr.src_addr = src_addr;
    ipv4_repr.dst_addr = dst_addr;
    payload[0..2].copy_from_slice(&src_port.to_be_bytes());
    payload[2..4].copy_from_slice(&dst_port.to_be_bytes());
    update_transport_checksum(protocol, ipv4_repr, payload);
}

fn transport_header_len(protocol: OutputRuleProtocol) -> usize {
    match protocol {
        OutputRuleProtocol::Tcp => 20,
        OutputRuleProtocol::Udp => 8,
        OutputRuleProtocol::Icmp => usize::MAX,
    }
}

/// 转发数据包经过 NAT 改写后，重新计算 TCP 或 UDP 校验和。
///
/// smoltcp 在发送本地生成的数据包表示时计算校验和。转发数据包有意保留原始传输层载荷，
/// 因此这个有界辅助函数会在以太网/IP 序列化前更新 RFC 793/768 伪首部校验和。
fn update_transport_checksum(
    protocol: OutputRuleProtocol,
    ipv4_repr: &Ipv4Repr,
    payload: &mut [u8],
) {
    let checksum_offset = match protocol {
        OutputRuleProtocol::Tcp => 16,
        OutputRuleProtocol::Udp => 6,
        OutputRuleProtocol::Icmp => return,
    };
    if payload.len() < checksum_offset + 2 {
        return;
    }

    payload[checksum_offset..checksum_offset + 2].fill(0);
    let protocol_number = match protocol {
        OutputRuleProtocol::Tcp => 6,
        OutputRuleProtocol::Udp => 17,
        OutputRuleProtocol::Icmp => return,
    };
    let mut sum = 0u32;
    sum = checksum_add(sum, &ipv4_repr.src_addr.octets());
    sum = checksum_add(sum, &ipv4_repr.dst_addr.octets());
    sum = sum.saturating_add(protocol_number);
    sum = sum.saturating_add(payload.len() as u32);
    sum = checksum_add(sum, payload);

    let mut checksum = checksum_finish(sum);
    // RFC 768 规定，计算结果为零的 UDP 校验和应编码为全一。
    if protocol == OutputRuleProtocol::Udp && checksum == 0 {
        checksum = u16::MAX;
    }
    payload[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn checksum_add(mut sum: u32, bytes: &[u8]) -> u32 {
    for chunk in bytes.chunks(2) {
        let word = match chunk {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from_be_bytes([*high, 0]),
            _ => 0,
        };
        sum = sum.saturating_add(u32::from(word));
    }
    sum
}

fn checksum_finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

impl MutableFilterRules {
    const fn new() -> Self {
        Self {
            rules: [None; MAX_FILTER_RULES],
            len: 0,
            policy: Action::Accept,
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
        conntrack_state: Option<ConntrackState>,
        target: OutputRuleTarget,
    ) -> bool {
        self.append_rule(OutputRule::transport(
            protocol,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            conntrack_state,
            target.into_action(),
        ))
    }

    fn insert_icmp_echo(
        &mut self,
        index: usize,
        ident: Option<u16>,
        src_addr: Option<Ipv4Address>,
        dst_addr: Option<Ipv4Address>,
        target: OutputRuleTarget,
    ) -> bool {
        self.insert_rule(
            index,
            OutputRule::icmp_echo(ident, src_addr, dst_addr, target.into_action()),
        )
    }

    fn insert_transport(
        &mut self,
        index: usize,
        protocol: OutputRuleProtocol,
        src_addr: Option<Ipv4Address>,
        dst_addr: Option<Ipv4Address>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        conntrack_state: Option<ConntrackState>,
        target: OutputRuleTarget,
    ) -> bool {
        self.insert_rule(
            index,
            OutputRule::transport(
                protocol,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                conntrack_state,
                target.into_action(),
            ),
        )
    }

    fn append_rule(&mut self, rule: OutputRule) -> bool {
        if self.len == MAX_FILTER_RULES {
            return false;
        }

        self.rules[self.len] = Some(rule);
        self.len += 1;
        true
    }

    fn insert_rule(&mut self, index: usize, rule: OutputRule) -> bool {
        if index > self.len || self.len == MAX_FILTER_RULES {
            return false;
        }

        for idx in (index..self.len).rev() {
            self.rules[idx + 1] = self.rules[idx];
        }
        self.rules[index] = Some(rule);
        self.len += 1;
        true
    }

    fn check_rule(&self, rule: OutputRule) -> bool {
        self.rules[..self.len]
            .iter()
            .flatten()
            .any(|current| current.same_configuration(rule))
    }

    fn replace(&mut self, index: usize, rule: OutputRule) -> bool {
        if index >= self.len {
            return false;
        }

        self.rules[index] = Some(rule);
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

    const fn policy(&self) -> Action {
        self.policy
    }

    fn set_policy(&mut self, policy: Action) {
        self.policy = policy;
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
        conntrack_state: ConntrackState,
        bytes: usize,
    ) -> Option<Verdict> {
        self.evaluate_first_match(bytes, |rule| {
            rule.matches_transport(protocol, context, src_port, dst_port, conntrack_state)
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

/// 描述可变 IPv4 过滤规则匹配的协议。
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

/// 过滤表可用的最小连接状态集合。
///
/// 在有界 NAT 表观察到首个回复 tuple 前，流处于 `New` 状态；观察到该反向数据包后
/// 变为 `Established`。RELATED、INVALID、TCP 状态机校验和协议辅助器有意不属于
/// 这个无分配的阶段 6 子集。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConntrackState {
    New,
    Established,
}

/// 描述可变 IPv4 过滤规则选择的终止目标。
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
        // 下方感知传输层的评估负责可变过滤策略。这里保持通用预解析入口宽松，
        // 以便在取得 TCP、UDP 或 ICMP 头后再考虑 ACCEPT 例外。
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
        let Icmpv4Repr::EchoRequest { ident, .. } = icmp_repr else {
            return FILTER_RULES[context.hook_point().index()].lock().policy().into();
        };

        let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(context.ipv4_repr().payload_len);
        let mut rules = FILTER_RULES[context.hook_point().index()].lock();
        if let Some(verdict) = rules.evaluate_matching_icmp_echo(context, *ident, packet_len) {
            return verdict;
        }

        rules.policy().into()
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
        // 获取过滤链锁前先解析 NAT 状态。连接跟踪查询会修改有界空闲时间戳，
        // 因而需要获取 NAT_RULES；分离两个锁的作用域可以避免转发期间
        // 过滤锁与 NAT 锁顺序反转。
        let conntrack_state =
            conntrack_state_for_transport(protocol, context.ipv4_repr(), src_port, dst_port);

        // NETFILTER_STAGE20：TCP/UDP 规则在 INPUT、OUTPUT 和 FORWARD 上
        // 使用相同的首条匹配链语义。
        let packet_len = IPV4_MIN_HEADER_LEN.saturating_add(context.ipv4_repr().payload_len);
        let mut rules = FILTER_RULES[context.hook_point().index()].lock();
        if let Some(verdict) =
            rules.evaluate_matching_transport(
                protocol,
                context,
                src_port,
                dst_port,
                conntrack_state,
                packet_len,
            )
        {
            return verdict;
        }

        rules.policy().into()
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

    for hook_point in [
        HookPoint::PreRouting,
        HookPoint::LocalIn,
        HookPoint::Forward,
        HookPoint::LocalOut,
        HookPoint::PostRouting,
    ] {
        let rules = FILTER_RULES[hook_point.index()].lock();
        writeln!(
            writer,
            "chain {} policy {}",
            FormatFilterChain(hook_point),
            FormatAction(rules.policy())
        )?;
        for (index, rule) in rules.rules[..rules.len()].iter().flatten().enumerate() {
            writeln!(
                writer,
                "  rule {} pkts {} bytes {} match{}{} {}{}{}{} target {}",
                index,
                rule.packets,
                rule.bytes,
                FormatIpv4Matcher::new(" src", rule.src_addr),
                FormatIpv4Matcher::new(" dst", rule.dst_addr),
                FormatProtocolMatcher(*rule),
                FormatPortMatcher::new(" sport", rule.src_port),
                FormatPortMatcher::new(" dport", rule.dst_port),
                FormatConntrackMatcher(rule.conntrack_state),
                FormatAction(rule.action),
            )?;
        }
        writeln!(
            writer,
            "state stage1-{}-rule-count {}",
            FormatFilterChain(hook_point),
            rules.len()
        )?;
        if hook_point == HookPoint::LocalOut {
            writeln!(writer, "state stage20-output-rule-count {}", rules.len())?;
        }
    }

    // NETFILTER_STAGE21: NAT rules are intentionally rendered in the same
    // procfs snapshot as the filter table so the small `iptables` shim can
    // implement `-t nat -L` without a second kernel ABI.
    let nat_rules = NAT_RULES.lock();
    writeln!(writer, "table nat")?;
    for chain in [NatRuleChain::PreRouting, NatRuleChain::PostRouting] {
        writeln!(writer, "chain {} policy ACCEPT", FormatNatChain(chain))?;
        let mut chain_index = 0;
        for rule in nat_rules.rules[..nat_rules.len()].iter().flatten() {
            if rule.chain != chain {
                continue;
            }
            writeln!(
                writer,
                "  rule {} pkts {} bytes {} match{}{}{}{}{} target {}{}{}",
                chain_index,
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
            chain_index += 1;
        }
        writeln!(
            writer,
            "state stage7-{}-nat-rule-count {}",
            FormatNatChain(chain),
            chain_index
        )?;
    }
    writeln!(writer, "state stage21-nat-rule-count {}", nat_rules.len())
}

/// Appends an OUTPUT-chain ICMP Echo rule.
pub fn append_output_icmp_echo_rule(
    ident: Option<u16>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    target: OutputRuleTarget,
) -> bool {
    append_filter_icmp_echo_rule(HookPoint::LocalOut, ident, src_addr, dst_addr, target)
}

/// 向一条内置 IPv4 链追加 ICMP Echo 过滤规则。
pub fn append_filter_icmp_echo_rule(
    hook_point: HookPoint,
    ident: Option<u16>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    target: OutputRuleTarget,
) -> bool {
    FILTER_RULES[hook_point.index()]
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
    conntrack_state: Option<ConntrackState>,
    target: OutputRuleTarget,
) -> bool {
    append_filter_transport_rule(
        HookPoint::LocalOut,
        protocol,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        conntrack_state,
        target,
    )
}

/// 向一条内置 IPv4 链追加 TCP 或 UDP 过滤规则。
pub fn append_filter_transport_rule(
    hook_point: HookPoint,
    protocol: OutputRuleProtocol,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    conntrack_state: Option<ConntrackState>,
    target: OutputRuleTarget,
) -> bool {
    FILTER_RULES[hook_point.index()]
        .lock()
        .append_transport(
            protocol,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            conntrack_state,
            target,
        )
}

/// 在一条链中从零开始的规则索引前插入 ICMP Echo 规则。
pub fn insert_filter_icmp_echo_rule(
    hook_point: HookPoint,
    index: usize,
    ident: Option<u16>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    target: OutputRuleTarget,
) -> bool {
    FILTER_RULES[hook_point.index()]
        .lock()
        .insert_icmp_echo(index, ident, src_addr, dst_addr, target)
}

/// 在一条链中从零开始的规则索引前插入 TCP 或 UDP 规则。
pub fn insert_filter_transport_rule(
    hook_point: HookPoint,
    index: usize,
    protocol: OutputRuleProtocol,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    conntrack_state: Option<ConntrackState>,
    target: OutputRuleTarget,
) -> bool {
    FILTER_RULES[hook_point.index()].lock().insert_transport(
        index,
        protocol,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        conntrack_state,
        target,
    )
}

/// 检查一条过滤链规则是否已存在。
pub fn check_filter_icmp_echo_rule(
    hook_point: HookPoint,
    ident: Option<u16>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    target: OutputRuleTarget,
) -> bool {
    FILTER_RULES[hook_point.index()]
        .lock()
        .check_rule(OutputRule::icmp_echo(ident, src_addr, dst_addr, target.into_action()))
}

/// 检查一条 TCP 或 UDP 过滤链规则是否已存在。
pub fn check_filter_transport_rule(
    hook_point: HookPoint,
    protocol: OutputRuleProtocol,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    conntrack_state: Option<ConntrackState>,
    target: OutputRuleTarget,
) -> bool {
    FILTER_RULES[hook_point.index()].lock().check_rule(OutputRule::transport(
        protocol,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        conntrack_state,
        target.into_action(),
    ))
}

/// 替换一条过滤链中从零开始编号的规则。
pub fn replace_filter_icmp_echo_rule(
    hook_point: HookPoint,
    index: usize,
    ident: Option<u16>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    target: OutputRuleTarget,
) -> bool {
    FILTER_RULES[hook_point.index()].lock().replace(
        index,
        OutputRule::icmp_echo(ident, src_addr, dst_addr, target.into_action()),
    )
}

/// 替换一条过滤链中从零开始编号的 TCP 或 UDP 规则。
pub fn replace_filter_transport_rule(
    hook_point: HookPoint,
    index: usize,
    protocol: OutputRuleProtocol,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    conntrack_state: Option<ConntrackState>,
    target: OutputRuleTarget,
) -> bool {
    FILTER_RULES[hook_point.index()].lock().replace(
        index,
        OutputRule::transport(
            protocol,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            conntrack_state,
            target.into_action(),
        ),
    )
}

/// 设置一条内置 IPv4 过滤链的默认策略。
pub fn set_filter_chain_policy(hook_point: HookPoint, target: OutputRuleTarget) {
    FILTER_RULES[hook_point.index()]
        .lock()
        .set_policy(target.into_action());
}

/// Deletes one OUTPUT-chain rule by index.
pub fn delete_output_rule(index: usize) -> bool {
    delete_filter_rule(HookPoint::LocalOut, index)
}

/// 从一条内置 IPv4 过滤链中删除一条规则。
pub fn delete_filter_rule(hook_point: HookPoint, index: usize) -> bool {
    FILTER_RULES[hook_point.index()].lock().delete(index)
}

/// Flushes all OUTPUT-chain rules.
pub fn flush_output_rules() {
    flush_filter_rules(HookPoint::LocalOut);
}

/// 清空一条内置 IPv4 过滤链。
pub fn flush_filter_rules(hook_point: HookPoint) {
    FILTER_RULES[hook_point.index()].lock().flush();
}

/// Clears packet and byte counters from all OUTPUT-chain rules.
pub fn zero_output_rule_counters() {
    zero_filter_rule_counters(HookPoint::LocalOut);
}

/// 清零一条内置 IPv4 过滤链中的计数器。
pub fn zero_filter_rule_counters(hook_point: HookPoint) {
    FILTER_RULES[hook_point.index()].lock().zero_counters();
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

/// 在一条 NAT 链中从零开始编号的位置插入 NAT 规则。
pub fn insert_nat_rule(
    chain: NatRuleChain,
    index: usize,
    protocol: Option<OutputRuleProtocol>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    target: NatRuleTarget,
    to_addr: Option<Ipv4Address>,
    to_port: Option<u16>,
) -> bool {
    NAT_RULES.lock().insert_rule(
        chain,
        index,
        NatRule::new(
            chain, protocol, src_addr, dst_addr, src_port, dst_port, target, to_addr, to_port,
        ),
    )
}

/// 检查任一内置链中是否已存在指定 NAT 规则。
pub fn check_nat_rule(
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
    NAT_RULES.lock().check_rule(NatRule::new(
        chain, protocol, src_addr, dst_addr, src_port, dst_port, target, to_addr, to_port,
    ))
}

/// 替换一条 NAT 链中从零开始编号的规则位置。
pub fn replace_nat_rule(
    chain: NatRuleChain,
    index: usize,
    protocol: Option<OutputRuleProtocol>,
    src_addr: Option<Ipv4Address>,
    dst_addr: Option<Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    target: NatRuleTarget,
    to_addr: Option<Ipv4Address>,
    to_port: Option<u16>,
) -> bool {
    NAT_RULES.lock().replace_rule(
        chain,
        index,
        NatRule::new(
            chain, protocol, src_addr, dst_addr, src_port, dst_port, target, to_addr, to_port,
        ),
    )
}

/// 删除一条链中从零开始编号的 NAT 规则位置。
pub fn delete_nat_rule(chain: NatRuleChain, index: usize) -> bool {
    NAT_RULES.lock().delete_rule(chain, index)
}

/// Flushes NAT rules from one chain or from the whole NAT table.
pub fn flush_nat_rules(chain: Option<NatRuleChain>) {
    NAT_RULES.lock().flush(chain);
}

/// 清零一条链或整张 NAT 表中的规则计数器。
pub fn zero_nat_rule_counters(chain: Option<NatRuleChain>) {
    NAT_RULES.lock().zero_counters(chain);
}

/// 在 IPv4 转发决策前应用有界有状态 NAT。
///
/// ICMP 保留阶段 3 的纯地址映射。TCP 和 UDP 还会为 DNAT 或反向 NAT 回复
/// 改写四元组和校验和。
pub fn rewrite_forwarded_ipv4_prerouting(ipv4_repr: &mut Ipv4Repr, payload: &mut [u8]) {
    NAT_RULES
        .lock()
        .rewrite_forwarded_prerouting(ipv4_repr, payload);
}

/// 确定出口接口后应用有界有状态 NAT。
///
/// MASQUERADE 目标使用选定接口的 IPv4 地址；SNAT 目标使用配置的 `--to-source`
/// 地址。规则未指定 TCP/UDP 源端口时，从固定范围内无冲突分配。
pub fn rewrite_forwarded_ipv4_postrouting(
    ipv4_repr: &mut Ipv4Repr,
    payload: &mut [u8],
    masquerade_addr: Option<Ipv4Address>,
) {
    NAT_RULES
        .lock()
        .rewrite_forwarded_postrouting(ipv4_repr, payload, masquerade_addr);
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

struct FormatFilterChain(HookPoint);

impl core::fmt::Display for FormatFilterChain {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            HookPoint::PreRouting => formatter.write_str("PREROUTING"),
            HookPoint::LocalIn => formatter.write_str("INPUT"),
            HookPoint::Forward => formatter.write_str("FORWARD"),
            HookPoint::LocalOut => formatter.write_str("OUTPUT"),
            HookPoint::PostRouting => formatter.write_str("POSTROUTING"),
        }
    }
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

struct FormatConntrackMatcher(Option<ConntrackState>);

impl core::fmt::Display for FormatConntrackMatcher {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Some(state) = self.0 else {
            return Ok(());
        };

        match state {
            ConntrackState::New => formatter.write_str(" ctstate NEW"),
            ConntrackState::Established => formatter.write_str(" ctstate ESTABLISHED"),
        }
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
