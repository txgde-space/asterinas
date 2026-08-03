// SPDX-License-Identifier: MPL-2.0

//! Types shared by the IPv4 forwarding data path and its platform integration.
//!
//! The forwarding decision is made by the platform because it owns the set of
//! interfaces and the routing policy.  This crate owns the bounded egress
//! queue and the packet serialization that sends a selected packet.

use alloc::vec::Vec;

use smoltcp::wire::{Ipv4Repr, Ipv6Address};

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

/// An IPv6 datagram that has passed ingress validation and is ready for an
/// egress interface.  IPv6 forwarding keeps the complete wire datagram so
/// extension headers and opaque transport payloads survive the router.  The
/// only mutation performed by the forwarding policy is the Hop Limit byte.
#[derive(Debug)]
pub struct ForwardedIpv6Packet {
    pub src_addr: Ipv6Address,
    pub dst_addr: Ipv6Address,
    bytes: Vec<u8>,
}

impl ForwardedIpv6Packet {
    const HEADER_LEN: usize = 40;

    /// Parses a complete IPv6 datagram copied from an Ethernet frame.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() < Self::HEADER_LEN || bytes[0] >> 4 != 6 {
            return None;
        }
        let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if Self::HEADER_LEN.saturating_add(payload_len) > bytes.len() {
            return None;
        }

        Some(Self {
            src_addr: Ipv6Address::new(
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
                u16::from_be_bytes([bytes[16], bytes[17]]),
                u16::from_be_bytes([bytes[18], bytes[19]]),
                u16::from_be_bytes([bytes[20], bytes[21]]),
                u16::from_be_bytes([bytes[22], bytes[23]]),
            ),
            dst_addr: Ipv6Address::new(
                u16::from_be_bytes([bytes[24], bytes[25]]),
                u16::from_be_bytes([bytes[26], bytes[27]]),
                u16::from_be_bytes([bytes[28], bytes[29]]),
                u16::from_be_bytes([bytes[30], bytes[31]]),
                u16::from_be_bytes([bytes[32], bytes[33]]),
                u16::from_be_bytes([bytes[34], bytes[35]]),
                u16::from_be_bytes([bytes[36], bytes[37]]),
                u16::from_be_bytes([bytes[38], bytes[39]]),
            ),
            bytes,
        })
    }

    pub fn hop_limit(&self) -> u8 {
        self.bytes[7]
    }

    pub fn decrement_hop_limit(&mut self) -> bool {
        if self.bytes[7] <= 1 {
            return false;
        }
        self.bytes[7] -= 1;
        true
    }

    pub fn buffer_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
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
