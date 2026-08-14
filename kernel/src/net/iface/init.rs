// SPDX-License-Identifier: MPL-2.0

use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::{
    slice::Iter,
    sync::atomic::{AtomicBool, Ordering},
};

use aster_bigtcp::{
    device::WithDevice,
    iface::{InterfaceFlags, InterfaceType},
};
use aster_softirq::BottomHalfDisabled;
use spin::Once;

use super::{Iface, poll::poll_ifaces};
use crate::{
    net::iface::{broadcast, sched::PollScheduler},
    prelude::*,
};

static IFACES: Once<Vec<Arc<Iface>>> = Once::new();
static STAGE2_MULTI_NIC_TEST: AtomicBool = AtomicBool::new(false);

aster_cmdline::define_flag_param!("netfilter.stage2_multi_nic", STAGE2_MULTI_NIC_TEST);

pub fn loopback_iface() -> &'static Arc<Iface> {
    &IFACES.get().unwrap()[0]
}

pub fn virtio_iface() -> Option<&'static Arc<Iface>> {
    IFACES.get().unwrap().get(1)
}

pub fn iter_all_ifaces() -> Iter<'static, Arc<Iface>> {
    IFACES.get().unwrap().iter()
}

pub fn init() {
    let virtio_devices = virtio_device_names();

    IFACES.call_once(|| {
        let mut ifaces = Vec::with_capacity(virtio_devices.len() + 1);

        // Initialize loopback before virtio
        // to ensure the loopback interface index is ahead of virtio.
        ifaces.push(new_loopback());

        for (index, device_name) in virtio_devices.iter().enumerate() {
            if let Some(iface_virtio) = new_virtio(device_name, index) {
                ifaces.push(iface_virtio);
            }
        }

        ifaces
    });

    for (device_name, iface_virtio) in virtio_devices.iter().zip(iter_all_ifaces().skip(1)) {
        let recv_callback = || iface_virtio.poll();
        let send_callback = || iface_virtio.poll();
        aster_network::register_recv_callback(device_name, recv_callback);
        aster_network::register_send_callback(device_name, send_callback);
    }

    broadcast::init();

    report_stage2_multi_nic_result();

    poll_ifaces();
}

fn report_stage2_multi_nic_result() {
    if !STAGE2_MULTI_NIC_TEST.load(Ordering::Relaxed) {
        return;
    }

    use aster_bigtcp::wire::Ipv4Address;

    let has_expected_iface = |name: &str, address: [u8; 4]| {
        iter_all_ifaces().any(|iface| {
            iface.name() == name
                && iface.ipv4_addr()
                    == Some(Ipv4Address::new(address[0], address[1], address[2], address[3]))
        })
    };

    if has_expected_iface("eth0", [10, 0, 2, 15])
        && has_expected_iface("eth1", [10, 0, 3, 15])
    {
        println!("netfilter-stage2a: multi-nic enumeration passed");
    } else {
        println!("netfilter-stage2a: multi-nic enumeration failed");
    }
}

fn virtio_device_names() -> Vec<String> {
    aster_network::all_devices()
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| {
            name.starts_with(aster_virtio::device::network::DEVICE_NAME_PREFIX)
                && name
                    .strip_prefix(aster_virtio::device::network::DEVICE_NAME_PREFIX)
                    .is_some_and(|suffix| suffix.starts_with('-'))
        })
        .collect()
}

fn new_loopback() -> Arc<Iface> {
    use aster_bigtcp::{
        device::{Loopback, Medium},
        iface::IpIface,
        wire::{Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6Cidr},
    };

    const LOOPBACK_ADDRESS: Ipv4Address = Ipv4Address::new(127, 0, 0, 1);
    const LOOPBACK_ADDRESS_PREFIX_LEN: u8 = 8; // mask: 255.0.0.0
    const LOOPBACK_IPV6_ADDRESS: Ipv6Address = Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1);
    const LOOPBACK_IPV6_PREFIX_LEN: u8 = 128;

    struct Wrapper(Mutex<Loopback>);

    impl WithDevice for Wrapper {
        type Device = Loopback;

        fn with<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&mut Self::Device) -> R,
        {
            let mut device = self.0.lock();
            f(&mut device)
        }
    }

    // FIXME: These flags are currently hardcoded.
    // In the future, we should set appropriate values.
    let flags = InterfaceFlags::UP
        | InterfaceFlags::LOOPBACK
        | InterfaceFlags::RUNNING
        | InterfaceFlags::LOWER_UP;

    IpIface::new(
        Wrapper(Mutex::new(Loopback::new(Medium::Ip))),
        Ipv4Cidr::new(LOOPBACK_ADDRESS, LOOPBACK_ADDRESS_PREFIX_LEN),
        Some(Ipv6Cidr::new(
            LOOPBACK_IPV6_ADDRESS,
            LOOPBACK_IPV6_PREFIX_LEN,
        )),
        "lo".to_owned(),
        PollScheduler::new(),
        InterfaceType::LOOPBACK,
        flags,
    ) as Arc<Iface>
}

fn new_virtio(device_name: &str, index: usize) -> Option<Arc<Iface>> {
    use aster_bigtcp::{
        iface::EtherIface,
        wire::{EthernetAddress, Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6Cidr},
    };
    use aster_network::AnyNetworkDevice;

    const VIRTIO_ADDRESS_PREFIX_LEN: u8 = 24; // mask: 255.255.255.0

    // QEMU 的第一张用户网络为 10.0.2.0/24，可选的第二张网络使用 10.0.3.0/24；
    // 更多接口沿用相同布局。
    let subnet = u8::try_from(index.checked_add(2)?).ok()?;
    let virtio_address = Ipv4Address::new(10, 0, subnet, 15);
    let virtio_gateway = Ipv4Address::new(10, 0, subnet, 2);
    let virtio_ipv6_address = Ipv6Address::new(
        0xfd00,
        0,
        0,
        u16::from(subnet),
        0,
        0,
        0,
        0x15,
    );
    let virtio_ipv6_gateway = Ipv6Address::new(
        0xfd00,
        0,
        0,
        u16::from(subnet),
        0,
        0,
        0,
        2,
    );

    let virtio_net = aster_network::get_device(device_name)?;

    let ether_addr = virtio_net.lock().mac_addr().0;

    struct Wrapper(Arc<SpinLock<dyn AnyNetworkDevice, BottomHalfDisabled>>);

    impl WithDevice for Wrapper {
        type Device = dyn AnyNetworkDevice;

        fn with<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&mut Self::Device) -> R,
        {
            let mut device = self.0.lock();
            f(&mut *device)
        }
    }

    // FIXME: These flags are currently hardcoded.
    // In the future, we should set appropriate values.
    let flags = InterfaceFlags::UP
        | InterfaceFlags::BROADCAST
        | InterfaceFlags::RUNNING
        | InterfaceFlags::MULTICAST
        | InterfaceFlags::LOWER_UP;

    Some(EtherIface::new(
        Wrapper(virtio_net),
        EthernetAddress(ether_addr),
        Ipv4Cidr::new(virtio_address, VIRTIO_ADDRESS_PREFIX_LEN),
        virtio_gateway,
        Ipv6Cidr::new(virtio_ipv6_address, 64),
        virtio_ipv6_gateway,
        alloc::format!("eth{index}"),
        PollScheduler::new(),
        flags,
    ))
}
