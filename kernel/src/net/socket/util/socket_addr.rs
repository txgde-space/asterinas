// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::wire::{Ipv4Address, PortNum};

use crate::{
    net::socket::{netlink::NetlinkSocketAddr, unix::UnixSocketAddr, vsock::VsockSocketAddr},
    prelude::*,
};

#[derive(Debug, Eq, PartialEq)]
pub enum SocketAddr {
    Unix(UnixSocketAddr),
    IPv4(Ipv4Address, PortNum),
    IPv6(Ipv6Address, PortNum, u32, u32),
    Netlink(NetlinkSocketAddr),
    Vsock(VsockSocketAddr),
}

/// A 128-bit IPv6 address used by the socket ABI.
///
/// The network dataplane is being enabled in stages. Keeping the address type
/// in the kernel socket layer lets AF_INET6 raw sockets work before the
/// Ethernet/router path grows IPv6 support, while preserving the exact
/// `sockaddr_in6` byte representation exposed to applications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6Address([u8; 16]);

impl Ipv6Address {
    pub const UNSPECIFIED: Self = Self([0; 16]);
    pub const LOOPBACK: Self = Self([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);

    pub const fn new(octets: [u8; 16]) -> Self {
        Self(octets)
    }

    pub const fn octets(self) -> [u8; 16] {
        self.0
    }

    pub fn is_unspecified(self) -> bool {
        self == Self::UNSPECIFIED
    }

    pub fn is_loopback(self) -> bool {
        self == Self::LOOPBACK
    }
}
