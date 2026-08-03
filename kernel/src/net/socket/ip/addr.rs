// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::wire::{IpAddress, IpEndpoint, Ipv4Address};

use crate::{
    net::{iface::BoundPort, socket::util::{Ipv6Address as SocketIpv6Address, SocketAddr}},
    prelude::*,
};

impl TryFrom<SocketAddr> for IpEndpoint {
    type Error = Error;

    fn try_from(value: SocketAddr) -> Result<Self> {
        match value {
            SocketAddr::IPv4(addr, port) => Ok(IpEndpoint::new(addr.into(), port)),
            _ => return_errno_with_message!(
                Errno::EAFNOSUPPORT,
                "the address is in an unsupported address family"
            ),
        }
    }
}

impl From<IpEndpoint> for SocketAddr {
    fn from(endpoint: IpEndpoint) -> Self {
        let port = endpoint.port;
        match endpoint.addr {
            IpAddress::Ipv4(addr) => SocketAddr::IPv4(addr, port),
            IpAddress::Ipv6(addr) => SocketAddr::IPv6(
                SocketIpv6Address::new(addr.octets()),
                port,
                0,
                0,
            ),
        }
    }
}

/// A local endpoint, which indicates that the local endpoint is unspecified.
///
/// According to the Linux man pages and the Linux implementation, `getsockname()` will _not_ fail
/// even if the socket is unbound. Instead, it will return an unspecified socket address. This
/// unspecified endpoint helps with that.
pub(super) const UNSPECIFIED_LOCAL_ENDPOINT: IpEndpoint =
    IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0);

/// 创建 bind() 成功后对用户态可见的本地端点。
pub(super) fn new_visible_local_endpoint(
    requested_endpoint: &IpEndpoint,
    bound_port: &BoundPort,
) -> IpEndpoint {
    // 绑定到 0.0.0.0 时，内部会选择实际接口地址收包；Linux 的 getsockname()
    // 仍然暴露用户传入的通配地址，只把端口替换成最终分配的端口。
    IpEndpoint::new(requested_endpoint.addr, bound_port.port())
}
