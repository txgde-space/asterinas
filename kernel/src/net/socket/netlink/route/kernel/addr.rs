// SPDX-License-Identifier: MPL-2.0

//! Handle address-related requests.

use core::num::NonZeroU32;

use super::util::finish_response;
use crate::{
    net::{
        iface::{Iface, iter_all_ifaces},
        socket::netlink::{
            message::{CMsgSegHdr, CSegmentType, GetRequestFlags, SegHdrCommonFlags},
            route::message::{
                AddrAttr, AddrMessageFlags, AddrSegment, AddrSegmentBody, RtScope, RtnlSegment,
            },
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

pub(super) fn do_get_addr(request_segment: &AddrSegment) -> Result<Vec<RtnlSegment>> {
    let dump_all = {
        let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
        flags.contains(GetRequestFlags::DUMP)
    };
    if !dump_all {
        return_errno_with_message!(Errno::EOPNOTSUPP, "GETADDR only supports dump requests");
    }

    // Keep the historical dump behavior for unknown family values: older
    // callers of this read-only implementation used them as an implicit
    // AF_UNSPEC request.  Explicit AF_INET6 now selects IPv6-only output.
    let family = match request_segment.body().family {
        family if family == CSocketAddrFamily::AF_INET as i32 => {
            CSocketAddrFamily::AF_INET as i32
        }
        family if family == CSocketAddrFamily::AF_INET6 as i32 => {
            CSocketAddrFamily::AF_INET6 as i32
        }
        _ => CSocketAddrFamily::AF_UNSPEC as i32,
    };

    let mut response_segments: Vec<RtnlSegment> = iter_all_ifaces()
        // GETADDR only supports dump mode, so we're going to report all addresses.
        .flat_map(|iface| iface_to_new_addrs(request_segment.header(), iface, family))
        .map(RtnlSegment::NewAddr)
        .collect();

    finish_response(request_segment.header(), dump_all, &mut response_segments);

    Ok(response_segments)
}

fn iface_to_new_addrs(
    request_header: &CMsgSegHdr,
    iface: &Arc<Iface>,
    family: i32,
) -> Vec<AddrSegment> {
    let header = CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWADDR as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    };

    let mut segments = Vec::new();
    if family == CSocketAddrFamily::AF_UNSPEC as i32
        || family == CSocketAddrFamily::AF_INET as i32
    {
        if let (Some(ipv4_addr), Some(prefix_len)) = (iface.ipv4_addr(), iface.prefix_len()) {
            let addr_message = AddrSegmentBody {
                family: CSocketAddrFamily::AF_INET as _,
                prefix_len,
                flags: AddrMessageFlags::PERMANENT,
                scope: RtScope::HOST,
                index: NonZeroU32::new(iface.index()),
            };
            let attrs = vec![
                AddrAttr::Address(ipv4_addr.octets()),
                AddrAttr::Label(CString::new(iface.name()).unwrap()),
                AddrAttr::Local(ipv4_addr.octets()),
            ];
            segments.push(AddrSegment::new(header, addr_message, attrs));
        }
    }
    if family == CSocketAddrFamily::AF_UNSPEC as i32
        || family == CSocketAddrFamily::AF_INET6 as i32
    {
        if let (Some(ipv6_addr), Some(prefix_len)) = (iface.ipv6_addr(), iface.ipv6_prefix_len()) {
            let addr_message = AddrSegmentBody {
                family: CSocketAddrFamily::AF_INET6 as _,
                prefix_len,
                flags: AddrMessageFlags::PERMANENT,
                scope: RtScope::HOST,
                index: NonZeroU32::new(iface.index()),
            };
            let attrs = vec![
                AddrAttr::AddressV6(ipv6_addr.octets()),
                AddrAttr::Label(CString::new(iface.name()).unwrap()),
                AddrAttr::LocalV6(ipv6_addr.octets()),
            ];
            segments.push(AddrSegment::new(header, addr_message, attrs));
        }
    }
    segments
}
