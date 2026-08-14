// SPDX-License-Identifier: MPL-2.0

use crate::{
    forwarding::{ForwardedIpv4Packet, ForwardedIpv6Packet, ForwardingResult},
    iface::ScheduleNextPoll,
    socket::SocketEventObserver,
};

/// Extension to be implemented by users of this crate.
///
/// This should be implemented on an empty type that carries no data, since the type will never
/// actually be instantiated.
///
/// The purpose of having this trait is to allow users of this crate to inject multiple types
/// without the hassle of writing multiple trait bounds, which can be achieved by using the types
/// associated with this trait.
pub trait Ext {
    /// The type for ifaces to schedule the next poll.
    type ScheduleNextPoll: ScheduleNextPoll;

    /// The type for TCP sockets to observe events.
    type TcpEventObserver: SocketEventObserver + Clone;

    /// The type for UDP sockets to observe events.
    type UdpEventObserver: SocketEventObserver;

    /// 对非本地 IPv4 数据包应用平台路由策略。
    ///
    /// 默认实现有意禁用转发，使 `aster-bigtcp` 的现有使用方在主动启用前
    /// 保持仅限本机的行为。
    fn forward_ipv4_packet(
        _ingress_ifindex: u32,
        _packet: ForwardedIpv4Packet,
    ) -> ForwardingResult {
        ForwardingResult::Disabled
    }

    /// 对非本地 IPv6 数据包应用平台路由策略。
    ///
    /// 默认实现有意禁用转发，使启用 IPv6 的 `aster-bigtcp` 使用方在主动启用前
    /// 保持仅限本机的行为。
    fn forward_ipv6_packet(
        _ingress_ifindex: u32,
        _packet: ForwardedIpv6Packet,
    ) -> ForwardingResult {
        ForwardingResult::Disabled
    }
}
