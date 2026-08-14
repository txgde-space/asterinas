// SPDX-License-Identifier: MPL-2.0

use crate::{
    net::socket::netlink::message::{Attribute, CAttrHeader, ContinueRead},
    prelude::*,
    util::MultiRead,
};

/// 路由级属性。
///
/// 参考：<https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/rtnetlink.h#L256>。
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
    DestinationV6([u8; 16]),
    OutputInterface(u32),
    Gateway([u8; 4]),
    GatewayV6([u8; 16]),
    Priority(u32),
    PreferredSource([u8; 4]),
    PreferredSourceV6([u8; 16]),
    Table(u32),
}

impl RouteAttr {
    fn class(&self) -> RouteAttrClass {
        match self {
            Self::Destination(_) | Self::DestinationV6(_) => RouteAttrClass::DST,
            Self::OutputInterface(_) => RouteAttrClass::OIF,
            Self::Gateway(_) | Self::GatewayV6(_) => RouteAttrClass::GATEWAY,
            Self::Priority(_) => RouteAttrClass::PRIORITY,
            Self::PreferredSource(_) | Self::PreferredSourceV6(_) => RouteAttrClass::PREFSRC,
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
            Self::Destination(address) | Self::Gateway(address) | Self::PreferredSource(address) => {
                address
            }
            Self::DestinationV6(address)
            | Self::GatewayV6(address)
            | Self::PreferredSourceV6(address) => address,
            Self::OutputInterface(index) | Self::Priority(index) | Self::Table(index) => {
                index.as_bytes()
            }
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>>
    where
        Self: Sized,
    {
        // 此实现接受的 GETROUTE 请求都是转储请求。其属性属于过滤条件，
        // 初始只读路由转储并不需要；消费并忽略这些属性，使 iproute2 能完成请求。
        reader.skip_some(header.payload_len());
        Ok(ContinueRead::Skipped)
    }
}
