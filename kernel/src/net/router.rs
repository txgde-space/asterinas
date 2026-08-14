// SPDX-License-Identifier: MPL-2.0

//! 阶段 2 IPv4 转发策略。
//!
//! 当前路由由已注册接口的 IPv4 直连前缀组成。静态路由、用户态控制面、
//! ICMP 专用错误、连接跟踪和 NAT 有意留给后续阶段。

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

/// 为阶段 2 转发流水线输出明确的启动标记。
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
            // IPv6 文本使用十六进制：虚拟服务 `::15` 以 0x15 结尾，
            // 而不是十进制 15（`::f`）。
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

    // TAP 验收拓扑无法在 guest 中运行交互式用户态命令。
    // 仅在显式测试标志存在时，安装与 iptables 解析器所创建规则相同的内核规则。
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

    // 阶段 4 使用显式启动标志，因为 TAP 验收环境还没有交互式 guest 侧规则管理 ABI。
    // 这些规则有意采用普通 TCP/UDP NAT 规则，使后续 iptables 兼容控制面可以复用
    // 相同的表 API。
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
        // 策略有意设为 DROP：双向 TCP 交换成功即可证明发出的 SYN 匹配 NEW，
        // 且回复 tuple 在 FORWARD 评估前已提升为 ESTABLISHED。
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

/// 选择直连出口路由并把数据包加入队列。
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

    // 在出口重新生成 Ipv4Repr，从而计算新的头校验和。
    packet.ip_repr.hop_limit -= 1;

    if !egress.enqueue_forwarded_ipv4(packet) {
        return ForwardingResult::QueueFull;
    }

    // 入口轮询仍持有接口锁时，不要同步轮询出口接口。
    // 否则立即回复可能经入口接口返回，并在同一把锁上永久自旋。
    let now_ms = Jiffies::elapsed().as_duration().as_millis() as u64;
    egress.sched_poll().schedule_next_poll(Some(now_ms));
    ForwardingResult::Queued
}

/// 选择直连 IPv6 出口路由并把数据包加入队列。
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

    // 仅在确定出口接口后评估 POSTROUTING，使 MASQUERADE 规则可以使用该接口的
    // IPv6 地址。NAT 模块还会记录反向 PREROUTING 路径使用的映射。
    aster_bigtcp::netfilter::apply_ipv6_nat_postrouting(
        &mut packet,
        egress.ipv6_addr(),
    );

    if !egress.enqueue_forwarded_ipv6(packet) {
        return ForwardingResult::QueueFull;
    }

    // 与 IPv4 路径相同，释放入口接口锁后再运行后台轮询器，避免嵌套接口轮询。
    let now_ms = Jiffies::elapsed().as_duration().as_millis() as u64;
    egress.sched_poll().schedule_next_poll(Some(now_ms));
    ForwardingResult::Queued
}

/// 查询 IPv4 目标地址对应的出口接口。
///
/// 直连前缀按最长前缀匹配胜出。如果没有直连路由匹配，则由配置了网关的接口提供
/// 默认路由。转发使用可选排除项，防止数据包重新排入其入口接口。
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

/// 查询 IPv6 目标地址对应的出口接口。
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
