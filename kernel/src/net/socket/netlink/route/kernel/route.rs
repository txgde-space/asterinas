// SPDX-License-Identifier: MPL-2.0

//! 处理只读 IPv4 和 IPv6 路由转储。

use aster_bigtcp::wire::{Ipv4Address, Ipv6Address};

use super::util::finish_response;
use crate::{
    net::{
        iface::{Iface, iter_all_ifaces},
        socket::netlink::{
            message::{CMsgSegHdr, CSegmentType, GetRequestFlags, SegHdrCommonFlags},
            route::message::{RouteAttr, RouteSegment, RouteSegmentBody, RtScope, RtnlSegment},
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

const RT_TABLE_MAIN: u8 = 254;
const RTPROT_KERNEL: u8 = 2;
const RTPROT_STATIC: u8 = 4;
const RTN_UNICAST: u8 = 1;

pub(super) fn do_get_route(request_segment: &RouteSegment) -> Result<Vec<RtnlSegment>> {
    let request_body = request_segment.body();
    if request_body.family != CSocketAddrFamily::AF_UNSPEC as i32
        && request_body.family != CSocketAddrFamily::AF_INET as i32
        && request_body.family != CSocketAddrFamily::AF_INET6 as i32
    {
        return_errno_with_message!(
            Errno::EAFNOSUPPORT,
            "only IPv4 and IPv6 route dumps are supported"
        );
    }

    let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
    if !flags.contains(GetRequestFlags::DUMP) {
        return_errno_with_message!(Errno::EOPNOTSUPP, "GETROUTE only supports dump requests");
    }

    let mut response_segments = Vec::new();
    for iface in iter_all_ifaces() {
        if request_body.family == CSocketAddrFamily::AF_UNSPEC as i32
            || request_body.family == CSocketAddrFamily::AF_INET as i32
        {
            append_ipv4_routes(request_segment.header(), iface, &mut response_segments);
        }
        if request_body.family == CSocketAddrFamily::AF_UNSPEC as i32
            || request_body.family == CSocketAddrFamily::AF_INET6 as i32
        {
            append_ipv6_routes(request_segment.header(), iface, &mut response_segments);
        }
    }

    finish_response(request_segment.header(), true, &mut response_segments);
    Ok(response_segments)
}

fn append_ipv4_routes(
    request_header: &CMsgSegHdr,
    iface: &Arc<Iface>,
    response_segments: &mut Vec<RtnlSegment>,
) {
    let (Some(address), Some(prefix_len)) = (iface.ipv4_addr(), iface.prefix_len()) else {
        return;
    };

    // 每个已配置的 IPv4 地址都会产生一条直连路由。
    let network = network_address(address, prefix_len);
    let connected_attrs = connected_route_attrs(iface, address, prefix_len, network);
    response_segments.push(RtnlSegment::NewRoute(RouteSegment::new(
        route_header(request_header),
        RouteSegmentBody {
            family: CSocketAddrFamily::AF_INET as i32,
            dst_len: prefix_len,
            src_len: 0,
            tos: 0,
            table: RT_TABLE_MAIN,
            protocol: RTPROT_KERNEL,
            scope: RtScope::LINK as u8,
            type_: RTN_UNICAST,
            flags: 0,
        },
        connected_attrs,
    )));

    // EtherIface 保存已配置的 smoltcp 下一跳。将其暴露为常规默认路由，
    // 使 `ip -4 route` 显示 Raw Socket 和传输层 Socket 所使用的相同路径。
    if let Some(gateway) = iface.ipv4_gateway() {
        let attrs = vec![
            RouteAttr::Gateway(gateway.octets()),
            RouteAttr::OutputInterface(iface.index()),
            RouteAttr::PreferredSource(address.octets()),
            RouteAttr::Table(u32::from(RT_TABLE_MAIN)),
        ];
        response_segments.push(RtnlSegment::NewRoute(RouteSegment::new(
            route_header(request_header),
            RouteSegmentBody {
                family: CSocketAddrFamily::AF_INET as i32,
                dst_len: 0,
                src_len: 0,
                tos: 0,
                table: RT_TABLE_MAIN,
                protocol: RTPROT_STATIC,
                scope: RtScope::UNIVERSE as u8,
                type_: RTN_UNICAST,
                flags: 0,
            },
            attrs,
        )));
    }
}

fn append_ipv6_routes(
    request_header: &CMsgSegHdr,
    iface: &Arc<Iface>,
    response_segments: &mut Vec<RtnlSegment>,
) {
    let (Some(address), Some(prefix_len)) = (iface.ipv6_addr(), iface.ipv6_prefix_len()) else {
        return;
    };

    let network = network_address_v6(address, prefix_len);
    let mut connected_attrs = vec![
        RouteAttr::OutputInterface(iface.index()),
        RouteAttr::PreferredSourceV6(address.octets()),
        RouteAttr::Table(u32::from(RT_TABLE_MAIN)),
    ];
    if prefix_len != 0 {
        connected_attrs.insert(0, RouteAttr::DestinationV6(network));
    }
    response_segments.push(RtnlSegment::NewRoute(RouteSegment::new(
        route_header(request_header),
        RouteSegmentBody {
            family: CSocketAddrFamily::AF_INET6 as i32,
            dst_len: prefix_len,
            src_len: 0,
            tos: 0,
            table: RT_TABLE_MAIN,
            protocol: RTPROT_KERNEL,
            scope: RtScope::LINK as u8,
            type_: RTN_UNICAST,
            flags: 0,
        },
        connected_attrs,
    )));

    if let Some(gateway) = iface.ipv6_gateway() {
        let attrs = vec![
            RouteAttr::GatewayV6(gateway.octets()),
            RouteAttr::OutputInterface(iface.index()),
            RouteAttr::PreferredSourceV6(address.octets()),
            RouteAttr::Table(u32::from(RT_TABLE_MAIN)),
        ];
        response_segments.push(RtnlSegment::NewRoute(RouteSegment::new(
            route_header(request_header),
            RouteSegmentBody {
                family: CSocketAddrFamily::AF_INET6 as i32,
                dst_len: 0,
                src_len: 0,
                tos: 0,
                table: RT_TABLE_MAIN,
                protocol: RTPROT_STATIC,
                scope: RtScope::UNIVERSE as u8,
                type_: RTN_UNICAST,
                flags: 0,
            },
            attrs,
        )));
    }
}

fn connected_route_attrs(
    iface: &Arc<Iface>,
    address: Ipv4Address,
    prefix_len: u8,
    network: [u8; 4],
) -> Vec<RouteAttr> {
    let mut attrs = vec![
        RouteAttr::OutputInterface(iface.index()),
        RouteAttr::PreferredSource(address.octets()),
        RouteAttr::Table(u32::from(RT_TABLE_MAIN)),
    ];
    if prefix_len != 0 {
        attrs.insert(0, RouteAttr::Destination(network));
    }
    attrs
}

fn route_header(request_header: &CMsgSegHdr) -> CMsgSegHdr {
    CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWROUTE as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    }
}

fn network_address(address: Ipv4Address, prefix_len: u8) -> [u8; 4] {
    let prefix_len = prefix_len.min(32);
    let bits = u32::from_be_bytes(address.octets());
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (bits & mask).to_be_bytes()
}

fn network_address_v6(address: Ipv6Address, prefix_len: u8) -> [u8; 16] {
    let prefix_len = prefix_len.min(128);
    let mut network = address.octets();
    for (index, octet) in network.iter_mut().enumerate() {
        let octet_start = index as u8 * 8;
        *octet = if prefix_len >= octet_start + 8 {
            *octet
        } else if prefix_len <= octet_start {
            0
        } else {
            let keep = prefix_len - octet_start;
            *octet & (u8::MAX << (8 - keep))
        };
    }
    network
}
