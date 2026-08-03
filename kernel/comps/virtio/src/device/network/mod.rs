// SPDX-License-Identifier: MPL-2.0

mod buffer;
mod config;
pub mod device;
mod header;

/// Prefix used to register virtio network devices.
///
/// Each virtio NIC must have a distinct registry key.  A fixed key caused a
/// second NIC to replace the first one in `aster_network`'s device table.
pub const DEVICE_NAME_PREFIX: &str = "Virtio-Net";

pub(crate) fn init() {
    buffer::init();
}
