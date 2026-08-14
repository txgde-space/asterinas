// SPDX-License-Identifier: MPL-2.0

mod buffer;
mod config;
pub mod device;
mod header;

/// 注册 VirtIO 网络设备时使用的前缀。
///
/// 每张 VirtIO 网卡必须拥有不同的注册键。使用固定键会导致第二张网卡替换
/// `aster_network` 设备表中的第一张网卡。
pub const DEVICE_NAME_PREFIX: &str = "Virtio-Net";

pub(crate) fn init() {
    buffer::init();
}
