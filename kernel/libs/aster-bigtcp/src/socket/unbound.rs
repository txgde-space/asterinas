// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, vec};

pub(super) type RawTcpSocket = smoltcp::socket::tcp::Socket<'static>;
pub type RawUdpSocket = smoltcp::socket::udp::Socket<'static>;

pub(super) fn new_tcp_socket() -> Box<RawTcpSocket> {
    let raw_tcp_socket = {
        let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; TCP_RECV_BUF_LEN]);
        let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; TCP_SEND_BUF_LEN]);
        RawTcpSocket::new(rx_buffer, tx_buffer)
    };
    Box::new(raw_tcp_socket)
}

pub(super) fn new_udp_socket() -> Box<RawUdpSocket> {
    let raw_udp_socket = {
        let metadata = smoltcp::socket::udp::PacketMetadata::EMPTY;
        let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![metadata; UDP_METADATA_LEN],
            vec![0u8; UDP_RECV_PAYLOAD_LEN],
        );
        let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![metadata; UDP_METADATA_LEN],
            vec![0u8; UDP_SEND_PAYLOAD_LEN],
        );
        RawUdpSocket::new(rx_buffer, tx_buffer)
    };
    Box::new(raw_udp_socket)
}

// TCP socket buffer sizes:
//
// Linux 默认缓冲区大致可按 256 packets * 256 bytes/packet 理解为 64 KiB。
// 但 loopback MTU 也是 64 KiB，缓冲区与 MTU 一样大时会触发 smoltcp 中 Nagle
// 算法实现的异常行为（见 https://github.com/asterinas/asterinas/pull/1396）。
//
// 当前兼容目标不实现 Linux 式 TCP buffer 自动调优。256 KiB 可以覆盖常见 HTTP
// 响应的首批写入，同时避免给每个 socket 引入过高的固定内存成本。
//
// TODO: Consider allowing user programs to set the socket buffer length via `setsockopt` system calls.
pub const TCP_RECV_BUF_LEN: usize = 65536 * 4;
pub const TCP_SEND_BUF_LEN: usize = 65536 * 4;

// UDP socket buffer sizes:
// UDP 单包受 IPv4 payload 上限约束，默认 64 KiB 足够覆盖常见 datagram 使用。
pub const UDP_SEND_PAYLOAD_LEN: usize = 65536;
pub const UDP_RECV_PAYLOAD_LEN: usize = 65536;
const UDP_METADATA_LEN: usize = 256;
