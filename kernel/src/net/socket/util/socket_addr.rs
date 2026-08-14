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

/// Socket ABI 使用的 128 位 IPv6 地址。
///
/// 网络数据面分阶段启用。把地址类型保留在内核 Socket 层，可以在以太网/路由器路径
/// 加入 IPv6 支持前先让 AF_INET6 Raw Socket 工作，同时保持向应用暴露的
/// `sockaddr_in6` 精确字节表示。
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
