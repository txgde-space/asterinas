// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    errors::udp::{RecvError, SendError},
    wire::IpEndpoint,
};

use crate::{
    events::IoEvents,
    net::{
        iface::{Iface, UdpSocket},
        socket::{
            ip::common::get_iface_for_remote,
            util::{datagram_common, SendRecvFlags},
        },
    },
    prelude::*,
    util::{MultiRead, MultiWrite},
};

pub(super) struct BoundDatagram {
    bound_sockets: Vec<UdpSocket>,
    local_endpoint: IpEndpoint,
    remote_endpoint: Option<IpEndpoint>,
}

impl BoundDatagram {
    pub(super) fn new(bound_sockets: Vec<UdpSocket>, local_endpoint: IpEndpoint) -> Self {
        debug_assert!(!bound_sockets.is_empty());
        Self {
            bound_sockets,
            local_endpoint,
            remote_endpoint: None,
        }
    }

    pub(super) fn ifaces(&self) -> impl Iterator<Item = &Arc<Iface>> {
        self.bound_sockets.iter().map(UdpSocket::iface)
    }

    pub(super) fn set_can_reuse(&self, can_reuse: bool) {
        for bound_socket in &self.bound_sockets {
            bound_socket.bound_port().set_can_reuse(can_reuse);
        }
    }

    pub(super) fn try_send_with_iface(
        &self,
        reader: &mut dyn MultiRead,
        remote: &IpEndpoint,
    ) -> Result<(usize, Arc<Iface>)> {
        let bound_socket = self.socket_for_remote(remote)?;
        let iface = bound_socket.iface().clone();
        let sent_bytes = Self::try_send_on_socket(bound_socket, reader, remote)?;
        Ok((sent_bytes, iface))
    }

    fn socket_for_remote(&self, remote: &IpEndpoint) -> Result<&UdpSocket> {
        if self.bound_sockets.len() == 1 {
            return Ok(&self.bound_sockets[0]);
        }

        let iface_index = get_iface_for_remote(&remote.addr).index();
        self.bound_sockets
            .iter()
            .find(|bound_socket| bound_socket.iface().index() == iface_index)
            .ok_or_else(|| {
                Error::with_message(
                    Errno::EADDRNOTAVAIL,
                    "the wildcard socket is not bound to the selected interface",
                )
            })
    }

    fn try_send_on_socket(
        bound_socket: &UdpSocket,
        reader: &mut dyn MultiRead,
        remote: &IpEndpoint,
    ) -> Result<usize> {
        let result = bound_socket.send(reader.sum_lens(), *remote, |socket_buffer| {
            // FIXME: 复制失败时不应发送任何数据包
            // 但当前 `smoltcp` API 似乎不支持此行为
            reader
                .read(&mut VmWriter::from(socket_buffer))
                .inspect_err(|e| {
                    warn!("unexpected UDP packet {e:#?} will be sent");
                })
        });

        match result {
            Ok(inner) => inner,
            Err(SendError::TooLarge) => {
                return_errno_with_message!(Errno::EMSGSIZE, "the message is too large");
            }
            Err(SendError::Unaddressable) => {
                return_errno_with_message!(Errno::EINVAL, "the destination address is invalid");
            }
            Err(SendError::BufferFull) => {
                return_errno_with_message!(Errno::EAGAIN, "the send buffer is full");
            }
        }
    }
}

impl datagram_common::Bound for BoundDatagram {
    type Endpoint = IpEndpoint;

    fn local_endpoint(&self) -> Self::Endpoint {
        self.local_endpoint
    }

    fn remote_endpoint(&self) -> Option<&Self::Endpoint> {
        self.remote_endpoint.as_ref()
    }

    fn set_remote_endpoint(&mut self, endpoint: &Self::Endpoint) {
        self.remote_endpoint = Some(*endpoint)
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        _flags: SendRecvFlags,
    ) -> Result<(usize, Self::Endpoint)> {
        for bound_socket in &self.bound_sockets {
            let result = bound_socket.recv(|packet, udp_metadata| {
                let copied_res = writer.write(&mut VmReader::from(packet));
                let endpoint = udp_metadata.endpoint;
                (copied_res, endpoint)
            });

            match result {
                Ok((Ok(res), endpoint)) => return Ok((res, endpoint)),
                Ok((Err(error), _)) => return Err(error),
                Err(RecvError::Exhausted) => continue,
                Err(RecvError::Truncated) => {
                    unreachable!("`recv` should never fail with `RecvError::Truncated`")
                }
            }
        }

        return_errno_with_message!(Errno::EAGAIN, "the receive buffer is empty")
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        remote: &Self::Endpoint,
        _flags: SendRecvFlags,
    ) -> Result<usize> {
        self.try_send_with_iface(reader, remote)
            .map(|(sent_bytes, _)| sent_bytes)
    }

    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::empty();
        if self
            .bound_sockets
            .iter()
            .any(|bound_socket| bound_socket.raw_with(|socket| socket.can_recv()))
        {
            events |= IoEvents::IN;
        }

        let can_send = if let Some(remote) = &self.remote_endpoint {
            self.socket_for_remote(remote)
                .ok()
                .is_some_and(|bound_socket| bound_socket.raw_with(|socket| socket.can_send()))
        } else {
            self.bound_sockets
                .iter()
                .any(|bound_socket| bound_socket.raw_with(|socket| socket.can_send()))
        };
        if can_send {
            events |= IoEvents::OUT;
        }

        events
    }
}
