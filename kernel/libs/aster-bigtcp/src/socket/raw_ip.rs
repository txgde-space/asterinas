// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::vec_deque::VecDeque, sync::Arc, vec::Vec};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::wire::{IpProtocol, Ipv4Address};

use crate::{
    ext::Ext,
    iface::Iface,
    socket::{SocketEventObserver, SocketEvents},
};

// RAW_SOCKET_STAGE2: Bound both dimensions because either many tiny packets or
// a few large packets could otherwise exhaust kernel memory.
const RAW_RECV_PACKET_LIMIT: usize = 64;
const RAW_RECV_BYTE_LIMIT: usize = 256 * 1024;
// RAW_SOCKET_STAGE3: Reuse the receive bounds for transmit so raw sockets
// cannot enqueue unbounded userspace-controlled packets.
const RAW_SEND_PACKET_LIMIT: usize = 64;
const RAW_SEND_BYTE_LIMIT: usize = 256 * 1024;

/// A complete IPv4 packet received by a raw IP socket.
pub struct RawIpv4Packet {
    bytes: Vec<u8>,
    source: Ipv4Address,
}

impl RawIpv4Packet {
    /// Returns the complete IPv4 packet, including its IPv4 header.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the packet source address.
    pub fn source(&self) -> Ipv4Address {
        self.source
    }
}

/// An IPv4 payload waiting to be transmitted by a raw IP socket.
pub(crate) struct RawIpv4TxPacket {
    destination: Ipv4Address,
    payload: Vec<u8>,
}

impl RawIpv4TxPacket {
    /// Returns the destination IPv4 address.
    pub(crate) fn destination(&self) -> Ipv4Address {
        self.destination
    }

    /// Returns the protocol payload, excluding the IPv4 header.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

struct RawRecvQueue {
    packets: VecDeque<RawIpv4Packet>,
    queued_bytes: usize,
}

impl RawRecvQueue {
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
            queued_bytes: 0,
        }
    }

    fn push(&mut self, packet: RawIpv4Packet) -> bool {
        let packet_len = packet.bytes.len();
        if self.packets.len() >= RAW_RECV_PACKET_LIMIT
            || self.queued_bytes.saturating_add(packet_len) > RAW_RECV_BYTE_LIMIT
        {
            return false;
        }

        self.queued_bytes += packet_len;
        self.packets.push_back(packet);
        true
    }

    fn pop(&mut self) -> Option<RawIpv4Packet> {
        let packet = self.packets.pop_front()?;
        self.queued_bytes -= packet.bytes.len();
        Some(packet)
    }
}

struct RawSendQueue {
    packets: VecDeque<RawIpv4TxPacket>,
    queued_bytes: usize,
}

impl RawSendQueue {
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
            queued_bytes: 0,
        }
    }

    fn push(&mut self, packet: RawIpv4TxPacket) -> bool {
        let packet_len = packet.payload.len();
        if self.packets.len() >= RAW_SEND_PACKET_LIMIT
            || self.queued_bytes.saturating_add(packet_len) > RAW_SEND_BYTE_LIMIT
        {
            return false;
        }

        self.queued_bytes += packet_len;
        self.packets.push_back(packet);
        true
    }

    fn pop(&mut self) -> Option<RawIpv4TxPacket> {
        let packet = self.packets.pop_front()?;
        self.queued_bytes -= packet.payload.len();
        Some(packet)
    }

    fn has_capacity(&self) -> bool {
        self.packets.len() < RAW_SEND_PACKET_LIMIT && self.queued_bytes < RAW_SEND_BYTE_LIMIT
    }
}

/// A raw IP socket attached to one interface.
pub struct RawIpSocket<E: Ext> {
    inner: Arc<RawIpSocketBg<E>>,
}

pub(crate) struct RawIpSocketBg<E: Ext> {
    iface: Arc<dyn Iface<E>>,
    protocol: IpProtocol,
    recv_queue: SpinLock<RawRecvQueue, BottomHalfDisabled>,
    send_queue: SpinLock<RawSendQueue, BottomHalfDisabled>,
    observer: Arc<dyn SocketEventObserver>,
}

impl<E: Ext> RawIpSocket<E> {
    /// Creates and registers a raw IP socket on an interface.
    pub fn new(
        iface: Arc<dyn Iface<E>>,
        protocol: IpProtocol,
        observer: Arc<dyn SocketEventObserver>,
    ) -> Self {
        let inner = Arc::new(RawIpSocketBg {
            iface: iface.clone(),
            protocol,
            recv_queue: SpinLock::new(RawRecvQueue::new()),
            send_queue: SpinLock::new(RawSendQueue::new()),
            observer,
        });

        // RAW_SOCKET_STAGE2: Registration is per interface because `aster-bigtcp`
        // currently owns independent socket tables for each interface.
        iface.common().register_raw_ip_socket(inner.clone());

        Self { inner }
    }

    /// Removes and returns the oldest received packet.
    pub fn recv(&self) -> Option<RawIpv4Packet> {
        self.inner.recv_queue.lock().pop()
    }

    /// Returns whether a packet is currently available.
    pub fn can_recv(&self) -> bool {
        !self.inner.recv_queue.lock().packets.is_empty()
    }

    /// Enqueues an IPv4 protocol payload for transmission.
    pub fn send_ipv4(&self, destination: Ipv4Address, payload: Vec<u8>) -> bool {
        // RAW_SOCKET_STAGE3: The syscall layer has already selected the route
        // and copied the userspace buffer, so this layer only enforces queue
        // bounds and schedules interface polling.
        let mut send_queue = self.inner.send_queue.lock();
        let was_full = !send_queue.has_capacity();
        let accepted = send_queue.push(RawIpv4TxPacket {
            destination,
            payload,
        });
        let can_send_more = send_queue.has_capacity();
        drop(send_queue);

        if accepted {
            self.inner.iface.poll();
        }

        if was_full && can_send_more {
            self.inner.observer.on_events(SocketEvents::CAN_SEND);
        }

        accepted
    }

    /// Returns whether another transmit packet can be accepted.
    pub fn can_send(&self) -> bool {
        self.inner.send_queue.lock().has_capacity()
    }

    /// Returns the local IPv4 address of the attached interface.
    pub fn local_ipv4_addr(&self) -> Option<Ipv4Address> {
        self.inner.iface.ipv4_addr()
    }
}

impl<E: Ext> Drop for RawIpSocket<E> {
    fn drop(&mut self) {
        self.inner.iface.common().remove_raw_ip_socket(&self.inner);
    }
}

impl<E: Ext> RawIpSocketBg<E> {
    pub(crate) fn protocol(&self) -> IpProtocol {
        self.protocol
    }

    pub(crate) fn pop_tx_packet(&self) -> Option<RawIpv4TxPacket> {
        let mut send_queue = self.send_queue.lock();
        let packet = send_queue.pop()?;
        let can_send_more = send_queue.has_capacity();
        drop(send_queue);

        if can_send_more {
            self.observer.on_events(SocketEvents::CAN_SEND);
        }

        Some(packet)
    }

    pub(crate) fn process_ipv4(&self, packet: &[u8], source: Ipv4Address) {
        let packet = RawIpv4Packet {
            bytes: packet.to_vec(),
            source,
        };

        let mut recv_queue = self.recv_queue.lock();
        let was_empty = recv_queue.packets.is_empty();
        if !recv_queue.push(packet) {
            return;
        }
        drop(recv_queue);

        if was_empty {
            self.observer.on_events(SocketEvents::CAN_RECV);
        }
    }
}
