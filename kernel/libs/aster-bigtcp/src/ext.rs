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

    /// Applies platform routing policy to a non-local IPv4 packet.
    ///
    /// The default deliberately disables forwarding so existing users of
    /// `aster-bigtcp` retain host-only behavior until they opt in.
    fn forward_ipv4_packet(
        _ingress_ifindex: u32,
        _packet: ForwardedIpv4Packet,
    ) -> ForwardingResult {
        ForwardingResult::Disabled
    }

    /// Applies platform routing policy to a non-local IPv6 packet.
    ///
    /// The default deliberately disables forwarding so IPv6-enabled users of
    /// `aster-bigtcp` retain host-only behavior until they opt in.
    fn forward_ipv6_packet(
        _ingress_ifindex: u32,
        _packet: ForwardedIpv6Packet,
    ) -> ForwardingResult {
        ForwardingResult::Disabled
    }
}
