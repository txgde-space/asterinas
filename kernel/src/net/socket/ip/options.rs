// SPDX-License-Identifier: MPL-2.0

use core::num::NonZeroU8;

use aster_bigtcp::socket::NeedIfacePoll;

use crate::{
    net::socket::options::{
        SocketOption,
        macros::{impl_socket_options, sock_option_mut, sock_option_ref},
    },
    prelude::*,
};

/// IP-level socket options.
#[derive(Clone, Copy, CopyGetters, Debug, Setters)]
#[get_copy = "pub"]
#[set = "pub"]
pub(super) struct IpOptionSet {
    tos: u8,
    ttl: IpTtl,
    hdrincl: bool,
    recverr: bool,
}

/// IPv6-level socket options used by raw IPv6 sockets.
#[derive(Clone, Copy, CopyGetters, Debug, Setters)]
#[get_copy = "pub"]
#[set = "pub"]
pub(super) struct Ipv6OptionSet {
    hop_limit: IpTtl,
    tclass: u8,
    hdrincl: bool,
    recverr: bool,
    recv_hoplimit: bool,
    recv_tclass: bool,
    v6only: bool,
}

const DEFAULT_TTL: u8 = 64;
pub(super) const INET_ECN_MASK: u8 = 3;

impl IpOptionSet {
    pub(super) const fn new_tcp() -> Self {
        Self {
            tos: 0,
            ttl: IpTtl(None),
            hdrincl: false,
            recverr: false,
        }
    }

    pub(super) const fn new_udp() -> Self {
        Self {
            tos: 0,
            ttl: IpTtl(None),
            hdrincl: false,
            recverr: false,
        }
    }

    pub(super) const fn new_raw() -> Self {
        Self {
            tos: 0,
            ttl: IpTtl(None),
            hdrincl: false,
            recverr: false,
        }
    }

    pub(super) fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            ip_tos @ Tos => {
                let tos = self.tos();
                ip_tos.set(tos as _);
            }
            ip_ttl @ Ttl => {
                let ttl = self.ttl();
                ip_ttl.set(ttl);
            }
            ip_hdrincl @ Hdrincl => {
                let hdrincl = self.hdrincl();
                ip_hdrincl.set(hdrincl);
            }
            ip_recverr @ Recverr => {
                let recverr = self.recverr();
                ip_recverr.set(recverr);
            }
            _ => return_errno_with_message!(Errno::ENOPROTOOPT, "the socket option is unknown"),
        });

        Ok(())
    }

    pub(super) fn set_option(
        &mut self,
        option: &dyn SocketOption,
        socket: &dyn SetIpLevelOption,
    ) -> Result<NeedIfacePoll> {
        sock_option_ref!(match option {
            ip_tos @ Tos => {
                let old_value = self.tos();
                let mut val = *ip_tos.get().unwrap() as u8;
                val &= !INET_ECN_MASK;
                val |= old_value & INET_ECN_MASK;
                self.set_tos(val);
            }
            ip_ttl @ Ttl => {
                let ttl = ip_ttl.get().unwrap();
                self.set_ttl(*ttl);
            }
            ip_hdrincl @ Hdrincl => {
                let hdrincl = ip_hdrincl.get().unwrap();
                socket.set_hdrincl(*hdrincl)?;
                self.set_hdrincl(*hdrincl);
            }
            ip_recverr @ Recverr => {
                let recverr = ip_recverr.get().unwrap();
                self.set_recverr(*recverr);
            }
            _ => return_errno_with_message!(
                Errno::ENOPROTOOPT,
                "the socket option to be set is unknown"
            ),
        });

        Ok(NeedIfacePoll::FALSE)
    }
}

impl Ipv6OptionSet {
    pub(super) const fn new_raw() -> Self {
        Self {
            hop_limit: IpTtl(None),
            tclass: 0,
            hdrincl: false,
            recverr: false,
            recv_hoplimit: false,
            recv_tclass: false,
            v6only: false,
        }
    }

    pub(super) fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            hop_limit @ Ipv6HopLimit => {
                hop_limit.set(self.hop_limit());
            }
            tclass @ Ipv6Tclass => {
                tclass.set(self.tclass() as i32);
            }
            hdrincl @ Hdrincl => {
                hdrincl.set(self.hdrincl());
            }
            recverr @ Ipv6Recverr => {
                recverr.set(self.recverr());
            }
            recv_hoplimit @ RecvHopLimit => {
                recv_hoplimit.set(self.recv_hoplimit());
            }
            recv_tclass @ RecvTclass => {
                recv_tclass.set(self.recv_tclass());
            }
            v6only @ V6Only => {
                v6only.set(self.v6only());
            }
            _ => return_errno_with_message!(Errno::ENOPROTOOPT, "the IPv6 socket option is unknown"),
        });

        Ok(())
    }

    pub(super) fn set_option(
        &mut self,
        option: &dyn SocketOption,
        socket: &dyn SetIpV6LevelOption,
    ) -> Result<NeedIfacePoll> {
        sock_option_ref!(match option {
            hop_limit @ Ipv6HopLimit => {
                self.set_hop_limit(*hop_limit.get().unwrap());
            }
            tclass @ Ipv6Tclass => {
                let value = *tclass.get().unwrap();
                if !(0..=u8::MAX as i32).contains(&value) {
                    return_errno_with_message!(Errno::EINVAL, "IPV6_TCLASS must fit in a byte");
                }
                self.set_tclass(value as u8);
            }
            hdrincl @ Hdrincl => {
                let hdrincl = *hdrincl.get().unwrap();
                socket.set_hdrincl(hdrincl)?;
                self.set_hdrincl(hdrincl);
            }
            recverr @ Ipv6Recverr => {
                self.set_recverr(*recverr.get().unwrap());
            }
            recv_hoplimit @ RecvHopLimit => {
                self.set_recv_hoplimit(*recv_hoplimit.get().unwrap());
            }
            recv_tclass @ RecvTclass => {
                self.set_recv_tclass(*recv_tclass.get().unwrap());
            }
            v6only @ V6Only => {
                self.set_v6only(*v6only.get().unwrap());
            }
            _ => return_errno_with_message!(
                Errno::ENOPROTOOPT,
                "the IPv6 socket option to be set is unknown"
            ),
        });

        Ok(NeedIfacePoll::FALSE)
    }
}

impl_socket_options!(
    pub struct Tos(i32);
    pub struct Ttl(IpTtl);
    pub struct Hdrincl(bool);
    pub struct Recverr(bool);
    pub struct Ipv6HopLimit(IpTtl);
    pub struct Ipv6Tclass(i32);
    pub struct Ipv6Recverr(bool);
    pub struct RecvHopLimit(bool);
    pub struct RecvTclass(bool);
    pub struct V6Only(bool);
);

#[derive(Clone, Copy, Debug)]
pub struct IpTtl(Option<NonZeroU8>);

impl IpTtl {
    pub const fn new(val: Option<NonZeroU8>) -> Self {
        Self(val)
    }

    pub const fn get(&self) -> u8 {
        if let Some(val) = self.0 {
            val.get()
        } else {
            DEFAULT_TTL
        }
    }
}

pub(super) trait SetIpLevelOption {
    fn set_hdrincl(&self, _hdrincl: bool) -> Result<()>;
}

pub(super) trait SetIpV6LevelOption {
    fn set_hdrincl(&self, _hdrincl: bool) -> Result<()>;
}
