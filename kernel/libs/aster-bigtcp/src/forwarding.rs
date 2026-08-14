// SPDX-License-Identifier: MPL-2.0

//! IPv4 转发数据路径及其平台集成所共享的类型。
//!
//! 转发决策由平台作出，因为平台持有接口集合和路由策略。本 crate 负责有界出口
//! 队列，以及发送选定数据包所需的序列化。

use alloc::vec::Vec;

use smoltcp::wire::{Ipv4Repr, Ipv6Address};

/// 已通过入口校验并可交给出口接口的 IPv4 数据报。
///
/// `ip_repr` 有意保存解析后的 IPv4 头。路由器递减跳数限制后，在出口重新生成该头
/// 会重算 IPv4 头校验和。阶段 2 不解析其余传输层载荷。
#[derive(Debug)]
pub struct ForwardedIpv4Packet {
    pub ip_repr: Ipv4Repr,
    pub payload: Vec<u8>,
    postrouting_nat_applied: bool,
}

/// 已通过入口校验并可交给出口接口的 IPv6 数据报。IPv6 转发保留完整线格式数据报，
/// 使扩展头和不透明传输层载荷能够穿过路由器。转发策略只修改 Hop Limit 字节。
#[derive(Debug)]
pub struct ForwardedIpv6Packet {
    pub src_addr: Ipv6Address,
    pub dst_addr: Ipv6Address,
    bytes: Vec<u8>,
}

impl ForwardedIpv6Packet {
    const HEADER_LEN: usize = 40;

    /// 解析从以太网帧复制出的完整 IPv6 数据报。
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() < Self::HEADER_LEN || bytes[0] >> 4 != 6 {
            return None;
        }
        let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if Self::HEADER_LEN.saturating_add(payload_len) > bytes.len() {
            return None;
        }

        Some(Self {
            src_addr: Ipv6Address::new(
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
                u16::from_be_bytes([bytes[16], bytes[17]]),
                u16::from_be_bytes([bytes[18], bytes[19]]),
                u16::from_be_bytes([bytes[20], bytes[21]]),
                u16::from_be_bytes([bytes[22], bytes[23]]),
            ),
            dst_addr: Ipv6Address::new(
                u16::from_be_bytes([bytes[24], bytes[25]]),
                u16::from_be_bytes([bytes[26], bytes[27]]),
                u16::from_be_bytes([bytes[28], bytes[29]]),
                u16::from_be_bytes([bytes[30], bytes[31]]),
                u16::from_be_bytes([bytes[32], bytes[33]]),
                u16::from_be_bytes([bytes[34], bytes[35]]),
                u16::from_be_bytes([bytes[36], bytes[37]]),
                u16::from_be_bytes([bytes[38], bytes[39]]),
            ),
            bytes,
        })
    }

    pub fn hop_limit(&self) -> u8 {
        self.bytes[7]
    }

    pub fn decrement_hop_limit(&mut self) -> bool {
        if self.bytes[7] <= 1 {
            return false;
        }
        self.bytes[7] -= 1;
        true
    }

    pub fn buffer_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 改写源地址并修复 IPv6 传输层校验和。
    pub(crate) fn rewrite_source_address(&mut self, address: Ipv6Address) -> bool {
        if !rewrite_ipv6_addresses(&mut self.bytes, Some(address), None) {
            return false;
        }
        self.src_addr = address;
        true
    }

    /// 改写目标地址并修复 IPv6 传输层校验和。
    pub(crate) fn rewrite_destination_address(&mut self, address: Ipv6Address) -> bool {
        if !rewrite_ipv6_addresses(&mut self.bytes, None, Some(address)) {
            return false;
        }
        self.dst_addr = address;
        true
    }
}

/// 改写序列化数据报中的一个或两个 IPv6 地址，并重算固定头 TCP、UDP 或 ICMPv6
/// 载荷的校验和。
///
/// 阶段 12 有意不解析扩展头链。对于使用扩展头的数据包，NAT 保持其不变，
/// 避免用错误的伪首部校验和进行改写。
pub(crate) fn rewrite_ipv6_addresses(
    bytes: &mut [u8],
    source: Option<Ipv6Address>,
    destination: Option<Ipv6Address>,
) -> bool {
    const HEADER_LEN: usize = 40;
    if bytes.len() < HEADER_LEN || bytes[0] >> 4 != 6 {
        return false;
    }

    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let end = HEADER_LEN.saturating_add(payload_len);
    if end > bytes.len() {
        return false;
    }

    let checksum_offset = match bytes[6] {
        6 => HEADER_LEN + 16,  // TCP 校验和
        17 => HEADER_LEN + 6,  // UDP 校验和
        58 => HEADER_LEN + 2,  // ICMPv6 校验和
        _ => return false,
    };
    if checksum_offset + 2 > end {
        return false;
    }

    if let Some(address) = source {
        bytes[8..24].copy_from_slice(&address.octets());
    }
    if let Some(address) = destination {
        bytes[24..40].copy_from_slice(&address.octets());
    }

    bytes[checksum_offset..checksum_offset + 2].fill(0);
    let checksum = ipv6_transport_checksum(&bytes[..end]);
    bytes[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
    true
}

fn ipv6_transport_checksum(bytes: &[u8]) -> u16 {
    const HEADER_LEN: usize = 40;

    fn add(mut sum: u32, bytes: &[u8]) -> u32 {
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
        }
        if let Some(&byte) = chunks.remainder().first() {
            sum = sum.wrapping_add((byte as u32) << 8);
        }
        sum
    }

    let payload_len = bytes.len().saturating_sub(HEADER_LEN);
    let mut sum = 0;
    sum = add(sum, &bytes[8..24]);
    sum = add(sum, &bytes[24..40]);
    sum = sum.wrapping_add((payload_len as u32) >> 16);
    sum = sum.wrapping_add((payload_len as u32) & 0xffff);
    sum = sum.wrapping_add(bytes[6] as u32);
    sum = add(sum, &bytes[HEADER_LEN..]);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

impl ForwardedIpv4Packet {
    pub fn new(ip_repr: Ipv4Repr, payload: Vec<u8>) -> Self {
        debug_assert_eq!(ip_repr.payload_len, payload.len());
        Self {
            ip_repr,
            payload,
            postrouting_nat_applied: false,
        }
    }

    /// 返回序列化该完整 IPv4 数据报所需的字节数。
    ///
    /// `Ipv4Repr::buffer_len` 只描述 IPv4 头。转发路径单独保存传输层载荷，
    /// 因此发送方在获取设备缓冲区前必须把两者长度相加。
    pub fn buffer_len(&self) -> usize {
        self.ip_repr.buffer_len().saturating_add(self.payload.len())
    }

    /// 返回是否已经执行过 POSTROUTING NAT 判定。
    ///
    /// 以太网解析 ARP 时，出口队列可能保留数据包。每个转发数据报只能执行一次 NAT，
    /// 而不能在每次重试时重复执行。
    pub fn postrouting_nat_applied(&self) -> bool {
        self.postrouting_nat_applied
    }

    /// 在完成 POSTROUTING NAT 决策后标记该数据包。
    pub fn mark_postrouting_nat_applied(&mut self) {
        self.postrouting_nat_applied = true;
    }
}

/// 请求平台转发策略路由数据包所得的结果。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardingResult {
    /// 数据包已被出口接口队列接收。
    Queued,
    /// IPv4 转发被管理配置禁用。
    Disabled,
    /// 没有符合条件的出口接口拥有到目标地址的路由。
    NoRoute,
    /// 数据包的跳数限制即将耗尽，无法继续转发。
    HopLimitExceeded,
    /// 选定的有界出口队列当前已满。
    QueueFull,
}
