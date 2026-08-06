// SPDX-License-Identifier: MPL-2.0

/// 默认临时端口范围的起始端口
pub const EPHEMERAL_PORT_START: u16 = 32768;

/// 默认临时端口范围的结束端口
pub const EPHEMERAL_PORT_END: u16 = 60999;

/// The configuration using for bind to a TCP/UDP port.
pub enum BindPortConfig {
    /// Binds to the specified non-reusable port.
    CanReuse(u16),
    /// Binds to the specified reusable port.
    Specified(u16),
    /// Allocates an ephemeral port to bind.
    Ephemeral(bool),
    /// Reuses the port of the listening socket.
    Backlog(u16),
}

impl BindPortConfig {
    /// Creates new configuration using for bind to a TCP/UDP port.
    pub fn new(port: u16, can_reuse: bool) -> Self {
        match (port, can_reuse) {
            (0, can_reuse) => Self::Ephemeral(can_reuse),
            (_, true) => Self::CanReuse(port),
            (_, false) => Self::Specified(port),
        }
    }

    pub(super) fn can_reuse(&self) -> bool {
        // accept 出来的连接沿用 listener 端口；把 backlog 端口计为可复用，避免
        // SO_REUSEADDR 服务重启被残留的已接受连接阻塞。
        matches!(self, Self::CanReuse(_) | Self::Backlog(_))
            || matches!(self, Self::Ephemeral(true))
    }

    pub(super) fn port(&self) -> Option<u16> {
        match self {
            Self::CanReuse(port) | Self::Specified(port) | Self::Backlog(port) => Some(*port),
            Self::Ephemeral(_) => None,
        }
    }
}
