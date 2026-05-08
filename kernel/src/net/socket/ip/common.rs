// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    errors::BindError,
    iface::BindPortConfig,
    wire::{IpAddress, IpEndpoint, Ipv4Address},
};

use crate::{
    net::{
        iface::{BoundPort, Iface, iter_all_ifaces, loopback_iface},
        socket::util::check_port_privilege,
    },
    prelude::*,
};

pub(super) fn get_iface_to_bind(ip_addr: &IpAddress) -> Option<Arc<Iface>> {
    let IpAddress::Ipv4(ipv4_addr) = ip_addr;
    if *ipv4_addr == Ipv4Address::UNSPECIFIED {
        // Linux 将 INADDR_ANY 视为服务端通配绑定。Asterinas 目前的 socket
        // 表还未跨接口共享，因此这里选择一个可提供 IPv4 服务的默认接口；
        // 没有对外接口时再退回 loopback，保证本机服务仍可启动。
        return Some(default_service_iface());
    }

    // 具体地址仍按精确匹配处理：127.0.0.1 只能绑定到 loopback，
    // 其他本机 IPv4 地址也必须绑定到拥有该地址的 iface，避免被通配绑定逻辑误导。
    iter_all_ifaces()
        .find(|iface| {
            if let Some(iface_ipv4_addr) = iface.ipv4_addr() {
                iface_ipv4_addr == *ipv4_addr
            } else {
                false
            }
        })
        .map(Clone::clone)
}

/// Get a suitable iface to deal with sendto/connect request if the socket is not bound to an iface.
/// If the remote address is the same as that of some iface, we will use the iface.
/// Otherwise, we will use a default interface.
fn get_ephemeral_iface(remote_ip_addr: &IpAddress) -> Arc<Iface> {
    let IpAddress::Ipv4(remote_ipv4_addr) = remote_ip_addr;
    if let Some(iface) = iter_all_ifaces().find(|iface| {
        if let Some(iface_ipv4_addr) = iface.ipv4_addr() {
            iface_ipv4_addr == *remote_ipv4_addr
        } else {
            false
        }
    }) {
        return iface.clone();
    }

    // FIXME: 当前先选择第一个可提供 IPv4 服务的接口；后续应按路由表选择默认接口。
    default_service_iface()
}

fn default_service_iface() -> Arc<Iface> {
    let loopback = loopback_iface();

    if let Some(iface) = iter_all_ifaces()
        .find(|iface| !Arc::ptr_eq(*iface, loopback) && iface.ipv4_addr().is_some())
    {
        return iface.clone();
    }

    loopback.clone()
}

pub(super) fn bind_port(endpoint: &IpEndpoint, can_reuse: bool) -> Result<BoundPort> {
    check_port_privilege(endpoint.port)?;

    let iface = match get_iface_to_bind(&endpoint.addr) {
        Some(iface) => iface,
        None => {
            return_errno_with_message!(
                Errno::EADDRNOTAVAIL,
                "the address is not available from the local machine"
            );
        }
    };

    let bind_port_config = BindPortConfig::new(endpoint.port, can_reuse);

    Ok(iface.bind(bind_port_config)?)
}

impl From<BindError> for Error {
    fn from(value: BindError) -> Self {
        match value {
            BindError::Exhausted => {
                Error::with_message(Errno::EAGAIN, "no ephemeral port is available")
            }
            BindError::InUse => {
                Error::with_message(Errno::EADDRINUSE, "the address is already in use")
            }
        }
    }
}

pub(super) fn get_ephemeral_endpoint(remote_endpoint: &IpEndpoint) -> IpEndpoint {
    let iface = get_ephemeral_iface(&remote_endpoint.addr);
    let ip_addr = iface.ipv4_addr().unwrap();
    IpEndpoint::new(IpAddress::Ipv4(ip_addr), 0)
}
