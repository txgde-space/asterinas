// SPDX-License-Identifier: MPL-2.0

use alloc::{string::String, sync::Arc};

use smoltcp::{
    iface::{Config, Context},
    phy::{Device, TxToken},
    wire::{self, Ipv4Cidr, Ipv4Packet},
};

use crate::{
    device::WithDevice,
    ext::Ext,
    forwarding::ForwardedIpv4Packet,
    socket::RawIpv4TxPacket,
    iface::{
        Iface, ScheduleNextPoll,
        common::{IfaceCommon, InterfaceFlags, InterfaceType},
        iface::internal::IfaceInternal,
        time::get_network_timestamp,
    },
};

pub struct IpIface<D, E: Ext> {
    driver: D,
    common: IfaceCommon<E>,
}

impl<D: WithDevice, E: Ext> IpIface<D, E> {
    pub fn new(
        driver: D,
        ip_cidr: Ipv4Cidr,
        name: String,
        sched_poll: E::ScheduleNextPoll,
        type_: InterfaceType,
        flags: InterfaceFlags,
    ) -> Arc<Self> {
        let interface = driver.with(|device| {
            let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
            let now = get_network_timestamp();

            let mut interface = smoltcp::iface::Interface::new(config, device, now);
            interface.update_ip_addrs(|ip_addrs| {
                debug_assert!(ip_addrs.is_empty());
                ip_addrs.push(wire::IpCidr::Ipv4(ip_cidr)).unwrap();
            });
            interface
        });

        let common = IfaceCommon::new(name, type_, flags, None, interface, sched_poll);

        Arc::new(Self { driver, common })
    }
}

impl<D, E: Ext> IfaceInternal<E> for IpIface<D, E> {
    fn common(&self) -> &IfaceCommon<E> {
        &self.common
    }
}

impl<D: WithDevice + 'static, E: Ext> Iface<E> for IpIface<D, E> {
    fn poll(&self) {
        self.driver.with(|device| {
            let next_poll = self.common.poll(
                device,
                |data, _iface_cx, tx_token| Some((Ipv4Packet::new_checked(data).ok()?, tx_token)),
                |pkt, iface_cx, tx_token| {
                    let ip_repr = pkt.ip_repr();
                    tx_token.consume(ip_repr.buffer_len(), |buffer| {
                        ip_repr.emit(&mut buffer[..], &iface_cx.checksum_caps());
                        pkt.emit_payload(
                            &ip_repr,
                            &mut buffer[ip_repr.header_len()..],
                            &iface_cx.caps,
                        );
                    });
                },
                |pkt: &ForwardedIpv4Packet, iface_cx, tx_token| {
                    tx_token.consume(pkt.buffer_len(), |buffer| {
                        let mut ip_packet = Ipv4Packet::new_unchecked(buffer);
                        pkt.ip_repr.emit(&mut ip_packet, &iface_cx.checksum_caps());
                        ip_packet.payload_mut().copy_from_slice(&pkt.payload);
                    });
                    true
                },
                |pkt, iface_cx, tx_token| self.dispatch_raw(pkt, iface_cx, tx_token),
            );
            self.common.sched_poll().schedule_next_poll(next_poll);
        });
    }

    fn mtu(&self) -> usize {
        self.driver
            .with(|device| device.capabilities().max_transmission_unit)
    }
}

impl<D: WithDevice + 'static, E: Ext> IpIface<D, E> {
    fn dispatch_raw<T: TxToken>(
        &self,
        pkt: &RawIpv4TxPacket,
        iface_cx: &mut Context,
        tx_token: T,
    ) {
        tx_token.consume(pkt.buffer_len(), |buffer| {
            pkt.emit_ipv4(buffer, &iface_cx.checksum_caps());
        });
    }
}
