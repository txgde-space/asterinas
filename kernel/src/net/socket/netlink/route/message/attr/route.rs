// SPDX-License-Identifier: MPL-2.0

use crate::{
    net::socket::netlink::message::{Attribute, CAttrHeader, ContinueRead},
    prelude::*,
    util::MultiRead,
};

/// Route-level attributes.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/rtnetlink.h#L256>.
#[expect(non_camel_case_types)]
#[expect(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum RouteAttrClass {
    UNSPEC = 0,
    DST = 1,
    SRC = 2,
    IIF = 3,
    OIF = 4,
    GATEWAY = 5,
    PRIORITY = 6,
    PREFSRC = 7,
    METRICS = 8,
    MULTIPATH = 9,
    PROTOINFO = 10,
    FLOW = 11,
    CACHEINFO = 12,
    SESSION = 13,
    MP_ALGO = 14,
    TABLE = 15,
}

#[derive(Debug)]
pub enum RouteAttr {
    Destination([u8; 4]),
    OutputInterface(u32),
    Gateway([u8; 4]),
    Priority(u32),
    PreferredSource([u8; 4]),
    Table(u32),
}

impl RouteAttr {
    fn class(&self) -> RouteAttrClass {
        match self {
            Self::Destination(_) => RouteAttrClass::DST,
            Self::OutputInterface(_) => RouteAttrClass::OIF,
            Self::Gateway(_) => RouteAttrClass::GATEWAY,
            Self::Priority(_) => RouteAttrClass::PRIORITY,
            Self::PreferredSource(_) => RouteAttrClass::PREFSRC,
            Self::Table(_) => RouteAttrClass::TABLE,
        }
    }
}

impl Attribute for RouteAttr {
    fn type_(&self) -> u16 {
        self.class() as u16
    }

    fn payload_as_bytes(&self) -> &[u8] {
        match self {
            Self::Destination(address)
            | Self::Gateway(address)
            | Self::PreferredSource(address) => address,
            Self::OutputInterface(index) | Self::Priority(index) | Self::Table(index) => {
                index.as_bytes()
            }
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>>
    where
        Self: Sized,
    {
        // GETROUTE requests accepted by this implementation are dump requests.  Their
        // attributes are filters that are not needed for the initial read-only route dump;
        // consume and ignore them so iproute2 can complete the request.
        reader.skip_some(header.payload_len());
        Ok(ContinueRead::Skipped)
    }
}
