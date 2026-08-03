// SPDX-License-Identifier: MPL-2.0

use align_ext::AlignExt;

use super::SocketAddr;
use crate::{net::socket::unix::UnixControlMessage, prelude::*, util::net::CSocketOptionLevel};

/// Message header used for sendmsg/recvmsg.
#[derive(Debug)]
pub struct MessageHeader {
    pub(in crate::net) addr: Option<SocketAddr>,
    pub(in crate::net) control_messages: Vec<ControlMessage>,
}

impl MessageHeader {
    /// Creates a new `MessageHeader`.
    pub const fn new(addr: Option<SocketAddr>, control_messages: Vec<ControlMessage>) -> Self {
        Self {
            addr,
            control_messages,
        }
    }

    /// Returns the socket address.
    pub fn addr(&self) -> Option<&SocketAddr> {
        self.addr.as_ref()
    }

    /// Returns the control messages.
    pub fn control_messages(&self) -> &Vec<ControlMessage> {
        &self.control_messages
    }
}

/// Control messages in [`MessageHeader`].
#[derive(Debug)]
pub enum ControlMessage {
    Unix(UnixControlMessage),
    Ip(IpControlMessage),
}

/// IPv4 ancillary data accepted by `sendmsg`.
///
/// Linux exposes these values as `int` payloads in a `SOL_IP` control
/// message.  Keeping the original integer here lets the socket layer perform
/// the same range validation as `setsockopt` while preserving the ABI shape
/// of the userspace control message.
#[derive(Debug)]
pub enum IpControlMessage {
    Tos(i32),
    Ttl(i32),
    ExtendedError(IpExtendedError),
}

/// Linux `struct sock_extended_err` carried by an `IP_RECVERR` cmsg.
///
/// The first implementation deliberately keeps the fixed 16-byte portion of
/// the ABI.  An offending address and quoted packet are added by a later
/// stage once the network stack has a common ICMP error delivery path.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct IpExtendedError {
    pub errno: u32,
    pub origin: u8,
    pub type_: u8,
    pub code: u8,
    pub pad: u8,
    pub info: u32,
    pub data: u32,
}

impl IpControlMessage {
    fn read_from(header: &CControlHeader, reader: &mut VmReader) -> Result<Option<Self>> {
        debug_assert_eq!(header.level(), Some(CSocketOptionLevel::SOL_IP));

        let message = match header.type_() {
            IP_TOS | IP_TTL => {
                if header.payload_len() != size_of::<i32>() {
                    return_errno_with_message!(Errno::EINVAL, "the IP control message is invalid");
                }
                let value = reader.read_val::<i32>()?;
                if header.type_() == IP_TOS {
                    Self::Tos(value)
                } else {
                    Self::Ttl(value)
                }
            }
            IP_RECVERR => {
                if header.payload_len() != size_of::<IpExtendedError>() {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "the extended IP error control message is invalid"
                    );
                }
                Self::ExtendedError(reader.read_val::<IpExtendedError>()?)
            }
            _ => {
                warn!("unsupported IPv4 control message type in {:?}", header);
                reader.skip(header.payload_len());
                return Ok(None);
            }
        };
        Ok(Some(message))
    }

    fn write_to(&self, writer: &mut VmWriter) -> Result<CControlHeader> {
        match self {
            Self::Tos(value) | Self::Ttl(value) => {
                let type_ = if matches!(self, Self::Tos(_)) {
                    IP_TOS
                } else {
                    IP_TTL
                };
                let header = CControlHeader::new(
                    CSocketOptionLevel::SOL_IP,
                    type_,
                    size_of::<i32>(),
                );
                writer.write_val(&header)?;
                writer.write_val(value)?;
                Ok(header)
            }
            Self::ExtendedError(error) => {
                let header = CControlHeader::new(
                    CSocketOptionLevel::SOL_IP,
                    IP_RECVERR,
                    size_of::<IpExtendedError>(),
                );
                writer.write_val(&header)?;
                writer.write_val(error)?;
                Ok(header)
            }
        }
    }
}

// Values from <netinet/in.h>.  They are deliberately local to the ancillary
// parser so the socket-option enum does not have to model cmsg type numbers.
const IP_TOS: i32 = 1;
const IP_TTL: i32 = 2;
const IP_RECVERR: i32 = 11;

impl ControlMessage {
    pub fn read_all_from(reader: &mut VmReader) -> Result<Vec<Self>> {
        // FIXME: This method may exhaust kernel memory and cause a panic if the program is
        // malicious and attempts to send too many control messages. To prevent this, we limit the
        // number of control messages, but this limit does not have a Linux equivalent.
        const MAX_NR_MSGS: usize = 32;

        let mut msgs = Vec::new();

        while reader.has_remain() && msgs.len() < MAX_NR_MSGS {
            let header = reader.read_val::<CControlHeader>()?;
            if header.len < size_of::<CControlHeader>() || header.payload_len() > reader.remain() {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "the size of the control message is invalid"
                );
            }

            if let Some(msg) = Self::read_from(&header, reader)? {
                msgs.push(msg);
            }

            let padding_len = header.padding_len().min(reader.remain());
            reader.skip(padding_len);
        }

        if reader.has_remain() {
            warn!("excessive control messages are currently not permitted");
            return_errno_with_message!(
                Errno::E2BIG,
                "excessive control messages are currently not permitted"
            );
        }

        Ok(msgs)
    }

    fn read_from(header: &CControlHeader, reader: &mut VmReader) -> Result<Option<Self>> {
        let Some(level) = header.level() else {
            warn!("unsupported control message level in {:?}", header);
            reader.skip(header.payload_len());
            return Ok(None);
        };

        match level {
            CSocketOptionLevel::SOL_SOCKET => {
                // Linux manual pages say (https://man7.org/linux/man-pages/man7/unix.7.html):
                // "For historical reasons, the ancillary message types listed below are specified
                // with a SOL_SOCKET type even though they are AF_UNIX specific."
                let msg = UnixControlMessage::read_from(header, reader)?;
                Ok(msg.map(Self::Unix))
            }
            CSocketOptionLevel::SOL_IP => {
                let msg = IpControlMessage::read_from(header, reader)?;
                Ok(msg.map(Self::Ip))
            }
            _ => {
                warn!("unsupported control message level in {:?}", header);
                reader.skip(header.payload_len());
                Ok(None)
            }
        }
    }

    pub fn write_all_to(msgs: &[Self], writer: &mut VmWriter) -> usize {
        let mut len = 0;

        for msg in msgs.iter() {
            let header = match msg.write_to(writer) {
                Ok(header) => header,
                // This occurs when the buffer is too short or when some page faults cannot be
                // handled. However, at this point, there is no good way to report the errors to
                // user space. According to the Linux implementation, it seems okay to silently
                // ignore errors here.
                Err(_) => {
                    warn!("setting MSG_CTRUNC is not supported");
                    break;
                }
            };

            len += header.total_len();

            let padding_len = header.padding_len().min(writer.avail());
            writer.skip(padding_len);
            len += padding_len;
        }

        len
    }

    fn write_to(&self, writer: &mut VmWriter) -> Result<CControlHeader> {
        match self {
            Self::Unix(msg) => msg.write_to(writer),
            Self::Ip(msg) => msg.write_to(writer),
        }
    }
}

/// `cmsghdr` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/linux/socket.h#L105>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct CControlHeader {
    /// Data byte count, including hdr
    len: usize,
    /// Originating protocol
    level: i32,
    /// Protocol-specific type
    type_: i32,
}

/// Alignment of control messages.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/linux/socket.h#L119>.
const CMSG_ALIGN: usize = size_of::<usize>();

impl CControlHeader {
    /// Creates a control message header with the level, type, and payload length.
    pub fn new(level: CSocketOptionLevel, type_: i32, payload_len: usize) -> Self {
        Self {
            len: payload_len + size_of::<Self>(),
            level: level as i32,
            type_,
        }
    }

    /// Computes the payload length from the total length.
    pub fn payload_len_from_total(total_len: usize) -> Result<usize> {
        total_len.checked_sub(size_of::<Self>()).ok_or_else(|| {
            Error::with_message(Errno::EINVAL, "the control message buffer is too small")
        })
    }

    /// Returns the level of the control message.
    pub fn level(&self) -> Option<CSocketOptionLevel> {
        CSocketOptionLevel::try_from(self.level).ok()
    }

    /// Returns the type of the control message.
    pub fn type_(&self) -> i32 {
        self.type_
    }

    /// Returns the payload length of the control message.
    pub fn payload_len(&self) -> usize {
        self.len - size_of::<Self>()
    }

    /// Returns the length of the control message (payload + header, excluding paddings).
    pub fn total_len(&self) -> usize {
        self.len
    }

    /// Returns the length of the padding bytes for the control message.
    pub(self) fn padding_len(&self) -> usize {
        self.total_len_with_padding() - self.total_len()
    }

    /// Returns the length of the control message (payload + header, including paddings).
    fn total_len_with_padding(&self) -> usize {
        self.len.align_up(CMSG_ALIGN)
    }
}
