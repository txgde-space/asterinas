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
    tcp_listeners: Vec<TcpListener>,
    local_endpoint: IpEndpoint,
}

impl ListenStream {
    pub(super) fn new(
        bound_ports: Vec<BoundPort>,
        local_endpoint: IpEndpoint,
        backlog: usize,
        option: &RawTcpOption,
        observer: StreamObserver,
    ) -> core::result::Result<Self, (Vec<BoundPort>, Error)> {
        // 保留 Linux SOMAXCONN 风格的上限约束，但当前最小实现不完整复刻
        // Linux 的 SYN 队列和 accept 队列双队列模型。
        const SOMAXCONN: usize = 4096;
        // 用 max_conn 控制 listener 可容纳的连接规模，满足常见服务的基本 backlog 需求。
        let max_conn = SOMAXCONN.min(backlog);

        let mut tcp_listeners = Vec::with_capacity(bound_ports.len());
        let mut remaining_ports = bound_ports.into_iter();

        while let Some(bound_port) = remaining_ports.next() {
            match TcpListener::new_listen(bound_port, max_conn, option, observer.clone()) {
                Ok(tcp_listener) => tcp_listeners.push(tcp_listener),
                Err((bound_port, err)) => {
                    let error = match err {
                        ListenError::AddressInUse => {
                            Error::with_message(Errno::EADDRINUSE, "listener key conflicts")
                        }
                        unexpected_error => unreachable!(
                            "`new_listen` fails with {:?}, which should not happen",
                            unexpected_error
                        ),
                    };
                    let mut recovered_ports = Vec::with_capacity(tcp_listeners.len() + 1);
                    for tcp_listener in tcp_listeners {
                        let Some(recovered_port) = tcp_listener.into_bound_port() else {
                            unreachable!("a newly created listener has no external references");
                        };
                        recovered_ports.push(recovered_port);
                    }
                    recovered_ports.push(bound_port);
                    recovered_ports.extend(remaining_ports);
                    return Err((recovered_ports, error));
                }
            }
        }

        Ok(Self {
            tcp_listeners,
            local_endpoint,
        })
    }

    pub(super) fn try_accept(&self) -> Result<ConnectedStream> {
        // listener 没有已完成连接时，按照非阻塞 accept 语义返回 EAGAIN。
        let Some((new_conn, remote_endpoint)) =
            self.tcp_listeners.iter().find_map(TcpListener::accept)
        else {
            return_errno_with_message!(Errno::EAGAIN, "no pending connection is available");
        };

        // 每次 accept 只取出一个 connected socket，listener 自身继续保留，
        // 因此可以支撑 HTTP/RPC 服务循环中的连续 accept。
        Ok(ConnectedStream::new(new_conn, remote_endpoint, false))
    }

    pub(super) fn local_endpoint(&self) -> IpEndpoint {
        self.local_endpoint
    }

    pub(super) fn iface(&self) -> &Arc<Iface> {
        self.tcp_listeners[0].iface()
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        // 内部 listener 状态中已经有待 accept 的连接时，
        // 对用户态 poll/select/epoll 应表现为可读事件。
        let can_accept = self.tcp_listeners.iter().any(TcpListener::can_accept);

        if can_accept {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }

    pub(super) fn set_raw_option<R>(&self, set_option: impl Fn(&dyn RawTcpSetOption) -> R) -> R {
        let mut tcp_listeners = self.tcp_listeners.iter();
        let Some(first_listener) = tcp_listeners.next() else {
            unreachable!("a listening stream always contains at least one listener");
        };
        let result = set_option(first_listener);
        for tcp_listener in tcp_listeners {
            set_option(tcp_listener);
        }
        result
    }

    pub(super) fn into_listeners(self) -> Vec<TcpListener> {
        self.tcp_listeners
    }
}
