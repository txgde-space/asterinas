// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use smoltcp::wire::{Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6Cidr};

use super::{BoundPort, InterfaceFlags, InterfaceType, port::BindPortConfig};
use crate::{
    errors::BindError,
    ext::Ext,
    forwarding::{ForwardedIpv4Packet, ForwardedIpv6Packet},
};

/// A network interface.
///
/// A network interface (abbreviated as iface) is a hardware or software component that connects a
/// computer to a network. Network interfaces can be physical components like Ethernet ports or
/// wireless adapters. They can also be virtual interfaces created by software, such as virtual
/// private network (VPN) connections.
pub trait Iface<E: Ext>: internal::IfaceInternal<E> + Send + Sync {
    /// Transmits or receives packets queued in the iface, and updates socket status accordingly.
    fn poll(&self);

    /// Returns the maximum transmission unit.
    fn mtu(&self) -> usize;

    /// 把已路由的 IPv4 数据报加入队列，等待从该接口发出。
    fn enqueue_forwarded_ipv4(&self, packet: ForwardedIpv4Packet) -> bool {
        self.common().enqueue_forwarded_ipv4(packet)
    }

    /// 把已路由的 IPv6 数据报加入队列，等待从该接口发出。
    fn enqueue_forwarded_ipv6(&self, packet: ForwardedIpv6Packet) -> bool {
        self.common().enqueue_forwarded_ipv6(packet)
    }
}

impl<E: Ext> dyn Iface<E> {
    /// Binds a socket to the iface.
    ///
    /// After binding the socket to the iface, the iface will handle all packets to and from the
    /// socket.
    ///
    /// If [`BindPortConfig::Ephemeral`] is specified, the iface will pick up an ephemeral port for
    /// the socket.
    ///
    /// FIXME: The reason for binding the socket and the iface together is because there are
    /// limitations inside smoltcp. See discussion at
    /// <https://github.com/smoltcp-rs/smoltcp/issues/779>.
    pub fn bind(
        self: &Arc<Self>,
        config: BindPortConfig,
    ) -> core::result::Result<BoundPort<E>, BindError> {
        let common = self.common();
        common.bind(self.clone(), config)
    }

    /// Returns the interface index.
    pub fn index(&self) -> u32 {
        self.common().index()
    }

    /// Gets the name of the iface.
    ///
    /// In Linux, the name is usually the driver name followed by a unit number.
    pub fn name(&self) -> &str {
        self.common().name()
    }

    /// Returns the interface type.
    pub fn type_(&self) -> InterfaceType {
        self.common().type_()
    }

    /// Returns the interface flags.
    pub fn flags(&self) -> InterfaceFlags {
        self.common().flags()
    }

    /// Gets the IPv4 address of the iface, if any.
    //
    // FIXME: One iface may have multiple IPv4 addresses.
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.common().ipv4_addr()
    }

    /// Retrieves the prefix length of the interface's IPv4 address.
    ///
    /// Both `Self::ipv4_addr` and this method will either return `Some(_)`
    /// or both will return `None`.
    pub fn prefix_len(&self) -> Option<u8> {
        self.common().prefix_len()
    }

    /// 获取已配置的 IPv4 下一跳网关（如果存在）。
    pub fn ipv4_gateway(&self) -> Option<Ipv4Address> {
        self.common().ipv4_gateway()
    }

    /// 获取接口已配置的 IPv6 地址（如果存在）。
    pub fn ipv6_addr(&self) -> Option<Ipv6Address> {
        self.common().ipv6_addr()
    }

    /// 获取接口 IPv6 地址的前缀长度。
    pub fn ipv6_prefix_len(&self) -> Option<u8> {
        self.common().ipv6_prefix_len()
    }

    /// 获取已配置的 IPv6 下一跳网关（如果存在）。
    pub fn ipv6_gateway(&self) -> Option<Ipv6Address> {
        self.common().ipv6_gateway()
    }

    /// 如果接口配置了 IPv6 CIDR，则返回该配置。
    pub fn ipv6_cidr(&self) -> Option<Ipv6Cidr> {
        Some(Ipv6Cidr::new(self.ipv6_addr()?, self.ipv6_prefix_len()?))
    }

    /// Gets the broadcast address of the iface, if any.
    pub fn broadcast_addr(&self) -> Option<Ipv4Address> {
        let cidr = {
            let common = self.common();
            let ipv4_addr = common.ipv4_addr()?;
            let prefix_len = common.prefix_len()?;
            Ipv4Cidr::new(ipv4_addr, prefix_len)
        };
        cidr.broadcast()
    }

    /// Returns a reference to the associated [`ScheduleNextPoll`].
    ///
    /// [`ScheduleNextPoll`]: crate::iface::sched::ScheduleNextPoll
    pub fn sched_poll(&self) -> &E::ScheduleNextPoll {
        self.common().sched_poll()
    }
}

pub(super) mod internal {
    use crate::{ext::Ext, iface::common::IfaceCommon};

    /// An internal trait that abstracts the common part of different ifaces.
    pub trait IfaceInternal<E> {
        fn common(&self) -> &IfaceCommon<E>
        where
            E: Ext;
    }
}
