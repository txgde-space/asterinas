// SPDX-License-Identifier: MPL-2.0

//! Types shared by the IPv4 forwarding data path and its platform integration.
//!
//! The forwarding decision is made by the platform because it owns the set of
//! interfaces and the routing policy.  This crate owns the bounded egress
//! queue and the packet serialization that sends a selected packet.

use alloc::vec::Vec;

use smoltcp::wire::Ipv4Repr;

/// An IPv4 datagram that has passed ingress validation and is ready for an
/// egress interface.
///
/// `ip_repr` deliberately contains a parsed IPv4 header.  Re-emitting it at
/// egress recalculates the IPv4 header checksum after the router decrements
/// the hop limit.  The transport payload is otherwise opaque in Stage 2.
#[derive(Debug)]
pub struct ForwardedIpv4Packet {
    pub ip_repr: Ipv4Repr,
    pub payload: Vec<u8>,
    postrouting_nat_applied: bool,
}

impl ForwardedIpv4Packet {
    pub fn new(ip_repr: Ipv4Repr, payload: Vec<u8>) -> Self {
        debug_assert_eq!(ip_repr.payload_len, payload.len());
        Self {
            ip_repr,
            payload,
            postrouting_nat_applied: false,
        }
    }

    /// Returns the bytes required to serialize this complete IPv4 datagram.
    ///
    /// `Ipv4Repr::buffer_len` describes the IPv4 header alone. The forwarding
    /// path keeps the transport payload separately, so transmitters must add
    /// both lengths before obtaining a device buffer.
    pub fn buffer_len(&self) -> usize {
        self.ip_repr.buffer_len().saturating_add(self.payload.len())
    }

    /// Returns whether POSTROUTING NAT has already been evaluated.
    ///
    /// The egress queue may retain a packet while Ethernet resolves ARP. NAT
    /// must run once per forwarded datagram rather than once per retry.
    pub fn postrouting_nat_applied(&self) -> bool {
        self.postrouting_nat_applied
    }

    /// Marks this packet after its POSTROUTING NAT decision is made.
    pub fn mark_postrouting_nat_applied(&mut self) {
        self.postrouting_nat_applied = true;
    }
}

/// Result of asking the platform forwarding policy to route a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardingResult {
    /// The packet was accepted by an egress interface queue.
    Queued,
    /// IPv4 forwarding is administratively disabled.
    Disabled,
    /// No eligible egress interface owns a route for the destination.
    NoRoute,
    /// The packet cannot be forwarded because its hop limit would expire.
    HopLimitExceeded,
    /// The selected egress queue is bounded and currently full.
    QueueFull,
}
