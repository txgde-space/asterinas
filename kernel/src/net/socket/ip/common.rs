// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    errors::BindError,
    iface::{BindPortConfig, EPHEMERAL_PORT_END, EPHEMERAL_PORT_START},
    wire::{IpAddress, IpEndpoint, Ipv4Address},
};

use crate::{
    net::{
        iface::{iter_all_ifaces, loopback_iface, BoundPort, Iface},
        router::lookup_ipv4_iface,
        socket::util::check_port_privilege,
    },
    prelude::*,
};

pub(super) fn get_iface_to_bind(ip_addr: &IpAddress) -> Option<Arc<Iface>> {
    let IpAddress::Ipv4(ipv4_addr) = ip_addr else {
        // The current transport socket tables are IPv4-only. Do not bind an
        // IPv6 endpoint to an IPv4 interface until the IPv6 transport path is
        // enabled.
        return None;
    };
    if *ipv4_addr == Ipv4Address::UNSPECIFIED {
        // Linux 将 `INADDR_ANY` 视为服务端通配绑定
        // 这里先选择默认 IPv4 接口完成初始端口预留，后续再将通配绑定
        // 扩展到所有 IPv4 接口，没有对外接口时回退到 loopback
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
pub(super) fn get_iface_for_remote(remote_ip_addr: &IpAddress) -> Arc<Iface> {
    let IpAddress::Ipv4(remote_ipv4_addr) = remote_ip_addr else {
        return default_service_iface();
    };
    if let Some(iface) = iter_all_ifaces().find(|iface| {
        iface
            .ipv4_addr()
            .is_some_and(|address| address == *remote_ipv4_addr)
    }) {
        return iface.clone();
    }

    if let Some(iface) = lookup_ipv4_iface(*remote_ipv4_addr, None) {
        return iface;
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

/// 在端点选定的每个接口上绑定同一端口
///
/// 对于 `INADDR_ANY:0`，会跨所有 IPv4 接口以原子方式预留候选端口，
/// 避免选中仅在默认接口上空闲、却已被其他接口占用的临时端口
pub(super) fn bind_port_set(endpoint: &IpEndpoint, can_reuse: bool) -> Result<Vec<BoundPort>> {
    let IpAddress::Ipv4(address) = endpoint.addr else {
        return Ok(Vec::from([bind_port(endpoint, can_reuse)?]));
    };
    if address != Ipv4Address::UNSPECIFIED || endpoint.port != 0 {
        let bound_port = bind_port(endpoint, can_reuse)?;
        return bind_wildcard_ports(bound_port, endpoint, can_reuse).map_err(|(error, _)| error);
    }

    check_port_privilege(endpoint.port)?;
    let ifaces: Vec<_> = iter_all_ifaces()
        .filter(|iface| iface.ipv4_addr().is_some())
        .cloned()
        .collect();
    if ifaces.is_empty() {
        return_errno_with_message!(
            Errno::EADDRNOTAVAIL,
            "no IPv4 interface is available for a wildcard binding"
        );
    }

    for port in EPHEMERAL_PORT_START..=EPHEMERAL_PORT_END {
        let mut bound_ports = Vec::with_capacity(ifaces.len());
        let mut has_conflict = false;

        for iface in &ifaces {
            match iface.bind(BindPortConfig::new(port, false)) {
                Ok(bound_port) => bound_ports.push(bound_port),
                Err(BindError::InUse) => {
                    has_conflict = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        if has_conflict {
            continue;
        }
        if can_reuse {
            for bound_port in &bound_ports {
                bound_port.set_can_reuse(true);
            }
        }
        return Ok(bound_ports);
    }

    Err(BindError::Exhausted.into())
}

/// 将 `INADDR_ANY` 绑定展开到每个 IPv4 接口
///
/// 第一个端口为原始绑定。若后续任一预留失败，本函数会释放已完成的全部预留，
/// 并将原始绑定返回给调用方
pub(super) fn bind_wildcard_ports(
    bound_port: BoundPort,
    visible_endpoint: &IpEndpoint,
    can_reuse: bool,
) -> core::result::Result<Vec<BoundPort>, (Error, BoundPort)> {
    let IpAddress::Ipv4(visible_addr) = visible_endpoint.addr else {
        return Ok(Vec::from([bound_port]));
    };
    if visible_addr != Ipv4Address::UNSPECIFIED {
        return Ok(Vec::from([bound_port]));
    }

    let original_iface_index = bound_port.iface().index();
    let port = bound_port.port();
    let mut bound_ports = Vec::with_capacity(iter_all_ifaces().len());
    bound_ports.push(bound_port);

    for iface in iter_all_ifaces() {
        if iface.index() == original_iface_index || iface.ipv4_addr().is_none() {
            continue;
        }

        let config = BindPortConfig::new(port, can_reuse);
        match iface.bind(config) {
            Ok(additional_bound_port) => bound_ports.push(additional_bound_port),
            Err(error) => {
                let original_bound_port = bound_ports.swap_remove(0);
                return Err((error.into(), original_bound_port));
            }
        }
    }

    Ok(bound_ports)
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
    let iface = get_iface_for_remote(&remote_endpoint.addr);
    let ip_addr = iface.ipv4_addr().unwrap();
    IpEndpoint::new(IpAddress::Ipv4(ip_addr), 0)
}
