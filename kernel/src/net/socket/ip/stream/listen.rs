// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    errors::tcp::ListenError,
    socket::{RawTcpOption, RawTcpSetOption},
    wire::IpEndpoint,
};

use super::{connected::ConnectedStream, observer::StreamObserver};
use crate::{
    events::IoEvents,
    net::iface::{BoundPort, Iface, TcpListener},
    prelude::*,
};

pub(super) struct ListenStream {
    tcp_listener: TcpListener,
    local_endpoint: IpEndpoint,
}

impl ListenStream {
    pub(super) fn new(
        bound_port: BoundPort,
        local_endpoint: IpEndpoint,
        backlog: usize,
        option: &RawTcpOption,
        observer: StreamObserver,
    ) -> core::result::Result<Self, (BoundPort, Error)> {
        // 保留 Linux SOMAXCONN 风格的上限约束，但当前最小实现不完整复刻
        // Linux 的 SYN 队列和 accept 队列双队列模型。
        const SOMAXCONN: usize = 4096;
        // 用 max_conn 控制 listener 可容纳的连接规模，满足常见服务的基本 backlog 需求。
        let max_conn = SOMAXCONN.min(backlog);

        match TcpListener::new_listen(bound_port, max_conn, option, observer) {
            Ok(tcp_listener) => Ok(Self {
                tcp_listener,
                local_endpoint,
            }),
            Err((bound_port, ListenError::AddressInUse)) => Err((
                bound_port,
                Error::with_message(Errno::EADDRINUSE, "listener key conflicts"),
            )),
            Err((_, err)) => {
                unreachable!("`new_listen` fails with {:?}, which should not happen", err)
            }
        }
    }

    pub(super) fn try_accept(&self) -> Result<ConnectedStream> {
        // listener 没有已完成连接时，按照非阻塞 accept 语义返回 EAGAIN。
        let (new_conn, remote_endpoint) = self.tcp_listener.accept().ok_or_else(|| {
            Error::with_message(Errno::EAGAIN, "no pending connection is available")
        })?;

        // 每次 accept 只取出一个 connected socket，listener 自身继续保留，
        // 因此可以支撑 HTTP/RPC 服务循环中的连续 accept。
        Ok(ConnectedStream::new(new_conn, remote_endpoint, false))
    }

    pub(super) fn local_endpoint(&self) -> IpEndpoint {
        self.local_endpoint
    }

    pub(super) fn iface(&self) -> &Arc<Iface> {
        self.tcp_listener.iface()
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        // 内部 listener 状态中已经有待 accept 的连接时，
        // 对用户态 poll/select/epoll 应表现为可读事件。
        let can_accept = self.tcp_listener.can_accept();

        if can_accept {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }

    pub(super) fn set_raw_option<R>(
        &self,
        set_option: impl FnOnce(&dyn RawTcpSetOption) -> R,
    ) -> R {
        set_option(&self.tcp_listener)
    }

    pub(super) fn into_listener(self) -> TcpListener {
        self.tcp_listener
    }
}
