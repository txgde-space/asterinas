// SPDX-License-Identifier: MPL-2.0

use int_to_c_enum::TryFromInt;

use super::{RawSocketOption, SocketOption, impl_raw_socket_option};
use crate::{
    net::socket::ip::options::{
        Hdrincl, Ipv6HopLimit, Ipv6Recverr, Ipv6Tclass, RecvHopLimit, RecvTclass, V6Only,
    },
    prelude::*,
};

/// Socket options for the IPv6 protocol level.
///
/// The numeric values follow `<netinet/in.h>`. This stage implements the
/// options needed by `ping -6`, raw diagnostics, and explicit per-packet
/// hop-limit/traffic-class control.
#[expect(non_camel_case_types)]
#[expect(clippy::upper_case_acronyms)]
#[repr(i32)]
#[derive(Clone, Copy, Debug, TryFromInt)]
pub enum CIpv6OptionName {
    UNICAST_HOPS = 16,
    RECVERR = 25,
    V6ONLY = 26,
    HDRINCL = 36,
    RECVHOPLIMIT = 51,
    RECVTCLASS = 66,
    TCLASS = 67,
}

pub fn new_ipv6_option(name: i32) -> Result<Box<dyn RawSocketOption>> {
    let name = CIpv6OptionName::try_from(name).map_err(|_| Errno::ENOPROTOOPT)?;
    match name {
        CIpv6OptionName::UNICAST_HOPS => Ok(Box::new(Ipv6HopLimit::new())),
        CIpv6OptionName::RECVERR => Ok(Box::new(Ipv6Recverr::new())),
        CIpv6OptionName::V6ONLY => Ok(Box::new(V6Only::new())),
        CIpv6OptionName::HDRINCL => Ok(Box::new(Hdrincl::new())),
        CIpv6OptionName::RECVHOPLIMIT => Ok(Box::new(RecvHopLimit::new())),
        CIpv6OptionName::RECVTCLASS => Ok(Box::new(RecvTclass::new())),
        CIpv6OptionName::TCLASS => Ok(Box::new(Ipv6Tclass::new())),
    }
}

impl_raw_socket_option!(Ipv6HopLimit);
impl_raw_socket_option!(Ipv6Recverr);
impl_raw_socket_option!(V6Only);
impl_raw_socket_option!(RecvHopLimit);
impl_raw_socket_option!(RecvTclass);
impl_raw_socket_option!(Ipv6Tclass);
