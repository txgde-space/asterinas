// SPDX-License-Identifier: MPL-2.0

use super::sched::PollScheduler;
use crate::net::socket::ip::{DatagramObserver, StreamObserver};

pub struct BigtcpExt;

impl aster_bigtcp::ext::Ext for BigtcpExt {
    type ScheduleNextPoll = PollScheduler;

    type TcpEventObserver = StreamObserver;
    type UdpEventObserver = DatagramObserver;

    fn forward_ipv4_packet(
        ingress_ifindex: u32,
        packet: aster_bigtcp::forwarding::ForwardedIpv4Packet,
    ) -> aster_bigtcp::forwarding::ForwardingResult {
        crate::net::router::forward_ipv4_packet(ingress_ifindex, packet)
    }

    fn forward_ipv6_packet(
        ingress_ifindex: u32,
        packet: aster_bigtcp::forwarding::ForwardedIpv6Packet,
    ) -> aster_bigtcp::forwarding::ForwardingResult {
        crate::net::router::forward_ipv6_packet(ingress_ifindex, packet)
    }
}
