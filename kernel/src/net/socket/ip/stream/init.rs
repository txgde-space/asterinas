// SPDX-License-Identifier: MPL-2.0

use core::{
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
};

use aster_bigtcp::{
    socket::RawTcpOption,
    wire::{IpAddress, IpEndpoint, Ipv4Address},
};

use super::{connecting::ConnectingStream, listen::ListenStream, observer::StreamObserver};
use crate::{
    events::IoEvents,
    net::{
        iface::BoundPort,
        socket::{
            ip::{
                addr::new_visible_local_endpoint,
                common::{bind_port, bind_wildcard_ports, get_ephemeral_endpoint},
            },
            util::SocketAddr,
        },
    },
    prelude::*,
};

pub(super) struct InitStream {
    bound_port: Option<BoundPort>,
    local_endpoint: Option<IpEndpoint>,
    /// Indicates if the last `connect()` is considered to be done.
    ///
    /// If `connect()` is called but we're still in the `InitStream`, this means that the
    /// connection is refused.
    ///
    ///  * If the connection is refused synchronously, the error code is returned by the
    ///    `connect()` system call, and after that we always consider the `connect()` to be already
    ///    done.
    ///
    ///  * If the connection is refused asynchronously (e.g., non-blocking sockets or interrupted
    ///    `connect()`), the last `connect()` is not considered to have been done until another
    ///    `connect()`, which checks and resets the boolean value and returns an appropriate error
    ///    code.
    is_connect_done: bool,
    /// Indicates whether the socket error is `ECONNREFUSED`.
    ///
    /// This boolean value is set to true when the connection is refused and set to false when the
    /// error code is reported via `getsockopt(SOL_SOCKET, SO_ERROR)`, `send()`, `recv()`, or
    /// `connect()`.
    is_conn_refused: AtomicBool,
}

impl InitStream {
    pub(super) fn new() -> Self {
        Self {
            bound_port: None,
            local_endpoint: None,
            is_connect_done: true,
            is_conn_refused: AtomicBool::new(false),
        }
    }

    fn new_bound_with_local_endpoint(
        bound_port: BoundPort,
        local_endpoint: Option<IpEndpoint>,
    ) -> Self {
        Self {
            bound_port: Some(bound_port),
            local_endpoint,
            is_connect_done: true,
            is_conn_refused: AtomicBool::new(false),
        }
    }

    pub(super) fn new_refused(bound_port: BoundPort) -> Self {
        let local_endpoint = bound_port.endpoint();
        Self::new_refused_with_local_endpoint(bound_port, local_endpoint)
    }

    fn new_refused_with_local_endpoint(
        bound_port: BoundPort,
        local_endpoint: Option<IpEndpoint>,
    ) -> Self {
        Self {
            bound_port: Some(bound_port),
            local_endpoint,
            is_connect_done: false,
            is_conn_refused: AtomicBool::new(true),
        }
    }

    pub(super) fn bind(&mut self, endpoint: &IpEndpoint, can_reuse: bool) -> Result<()> {
        if self.bound_port.is_some() {
            return_errno_with_message!(Errno::EINVAL, "the socket is already bound to an address");
        }

        let bound_port = bind_port(endpoint, can_reuse)?;
        let local_endpoint = new_visible_local_endpoint(endpoint, &bound_port);
        self.bound_port = Some(bound_port);
        self.local_endpoint = Some(local_endpoint);

        Ok(())
    }

    pub(super) fn bound_port(&self) -> Option<&BoundPort> {
        self.bound_port.as_ref()
    }

    pub(super) fn connect(
        self,
        remote_endpoint: &IpEndpoint,
        option: &RawTcpOption,
        can_reuse: bool,
        observer: StreamObserver,
    ) -> core::result::Result<ConnectingStream, (Error, Self)> {
        debug_assert!(
            self.is_connect_done,
            "`finish_last_connect()` should be called before calling `connect()`"
        );

        let (bound_port, local_endpoint) = if let Some(bound_port) = self.bound_port {
            (bound_port, self.local_endpoint)
        } else {
            let endpoint = get_ephemeral_endpoint(remote_endpoint);
            match bind_port(&endpoint, can_reuse) {
                Ok(bound_port) => {
                    let local_endpoint = new_visible_local_endpoint(&endpoint, &bound_port);
                    (bound_port, Some(local_endpoint))
                }
                Err(err) => return Err((err, self)),
            }
        };

        ConnectingStream::new(bound_port, *remote_endpoint, option, observer).map_err(
            |(err, bound_port)| {
                if err.error() == Errno::ECONNREFUSED {
                    (
                        err,
                        InitStream::new_refused_with_local_endpoint(bound_port, local_endpoint),
                    )
                } else {
                    (
                        err,
                        InitStream::new_bound_with_local_endpoint(bound_port, local_endpoint),
                    )
                }
            },
        )
    }

    pub(super) fn finish_last_connect(&mut self) -> Result<()> {
        if self.is_connect_done {
            return Ok(());
        }

        self.is_connect_done = true;

        let is_conn_refused = self.is_conn_refused.get_mut();
        if *is_conn_refused {
            *is_conn_refused = false;
            return_errno_with_message!(Errno::ECONNREFUSED, "the connection is refused");
        } else {
            return_errno_with_message!(
                Errno::ECONNABORTED,
                "the error code for the connection failure is not available"
            );
        }
    }

    pub(super) fn listen(
        self,
        backlog: usize,
        option: &RawTcpOption,
        can_reuse: bool,
        observer: StreamObserver,
    ) -> core::result::Result<ListenStream, (Error, Self)> {
        if !self.is_connect_done {
            // See the comments of `is_connect_done`.
            // `listen()` is also not allowed until the second `connect()`.
            return Err((
                Error::with_message(
                    Errno::EINVAL,
                    "the connection is refused, but the connecting phase is not done",
                ),
                self,
            ));
        }

        let (bound_port, local_endpoint) = if let Some(bound_port) = self.bound_port {
            // 已经显式 bind() 过的 socket，继续使用原有用户可见本地端点。
            let local_endpoint = self
                .local_endpoint
                .unwrap_or_else(|| bound_port.endpoint().unwrap());
            (bound_port, local_endpoint)
        } else {
            // Linux 允许未 bind 的 TCP socket 直接 listen()；
            // 内核会隐式绑定到 INADDR_ANY:0，再分配一个临时端口。
            let endpoint = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0);
            match bind_port(&endpoint, can_reuse) {
                Ok(bound_port) => {
                    // 对内部来说，aster-bigtcp 可以使用具体 iface 地址收包；
                    // 对用户态来说，getsockname() 仍应看到 0.0.0.0:<ephemeral-port>。
                    let local_endpoint = new_visible_local_endpoint(&endpoint, &bound_port);
                    (bound_port, local_endpoint)
                }
                Err(err) => return Err((err, self)),
            }
        };

        let bound_ports = match bind_wildcard_ports(bound_port, &local_endpoint, can_reuse) {
            Ok(bound_ports) => bound_ports,
            Err((error, bound_port)) => {
                return Err((
                    error,
                    Self::new_bound_with_local_endpoint(bound_port, Some(local_endpoint)),
                ));
            }
        };

        match ListenStream::new(bound_ports, local_endpoint, backlog, option, observer) {
            Ok(listen_stream) => Ok(listen_stream),
            Err((bound_ports, error)) => {
                let Some(bound_port) = bound_ports.into_iter().next() else {
                    unreachable!("a listener binding set always contains the original port");
                };
                Err((
                    error,
                    Self::new_bound_with_local_endpoint(bound_port, Some(local_endpoint)),
                ))
            }
        }
    }

    pub(super) fn try_recv(&self) -> Result<(usize, SocketAddr)> {
        // FIXME: Linux does not return addresses for `recvfrom` on connection-oriented sockets.
        // This is a placeholder that has no Linux equivalent. (Note also that in this case
        // `getpeeraddr` will simply fail with `ENOTCONN`).
        const UNSPECIFIED_SOCKET_ADDR: SocketAddr = SocketAddr::IPv4(Ipv4Addr::UNSPECIFIED, 0);

        // Below are some magic checks to make our behavior identical to Linux.

        if self.is_connect_done {
            return_errno_with_message!(Errno::ENOTCONN, "the socket is not connected");
        }

        if let Some(err) = self.test_and_clear_error() {
            return Err(err);
        }

        Ok((0, UNSPECIFIED_SOCKET_ADDR))
    }

    pub(super) fn try_send(&self) -> Result<usize> {
        if let Some(err) = self.test_and_clear_error() {
            return Err(err);
        }

        return_errno_with_message!(Errno::EPIPE, "the socket is not connected");
    }

    pub(super) fn local_endpoint(&self) -> Option<IpEndpoint> {
        self.local_endpoint
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        // Linux adds OUT and HUP events for a newly created socket
        let mut events = IoEvents::OUT | IoEvents::HUP;

        if self.is_conn_refused.load(Ordering::Relaxed) {
            events |= IoEvents::ERR;
        }

        events
    }

    pub(super) fn test_and_clear_error(&self) -> Option<Error> {
        if self.is_conn_refused.swap(false, Ordering::Relaxed) {
            Some(Error::with_message(
                Errno::ECONNREFUSED,
                "the connection is refused",
            ))
        } else {
            None
        }
    }
}
