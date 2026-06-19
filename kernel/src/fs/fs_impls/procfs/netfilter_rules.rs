// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{FileOps, ProcFileBuilder},
        vfs::inode::Inode,
    },
    prelude::*,
};

/// Represents the inode at `/proc/netfilter_rules`.
pub struct NetfilterRulesFileOps;

impl NetfilterRulesFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // NETFILTER_STAGE20: The iptables-like control surface now accepts
        // TCP/UDP source and destination port matchers in addition to ICMP.
        ProcFileBuilder::new(Self, mkmod!(a+r, u+w))
            .parent(parent)
            .build()
            .unwrap()
    }
}

impl FileOps for NetfilterRulesFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        aster_bigtcp::netfilter::write_filter_table_snapshot(&mut printer).map_err(|_| {
            Error::with_message(Errno::EIO, "failed to render netfilter rule table")
        })?;

        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        const MAX_COMMAND_LEN: usize = 320;

        let (command, bytes_read) = reader.read_cstring_until_end(MAX_COMMAND_LEN)?;
        let command = command
            .to_str()
            .ok()
            .map(|command| command.trim())
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid netfilter command"))?;

        if let Some(command) = parse_iptables_command(command)? {
            apply_command(command)?;
            return Ok(bytes_read);
        }

        if command == "flush OUTPUT" {
            aster_bigtcp::netfilter::flush_output_rules();
            return Ok(bytes_read);
        }

        if command == "zero OUTPUT" {
            aster_bigtcp::netfilter::zero_output_rule_counters();
            return Ok(bytes_read);
        }

        if let Some(index) = parse_delete_output_command(command)? {
            if !aster_bigtcp::netfilter::delete_output_rule(index) {
                return_errno_with_message!(Errno::EINVAL, "no such netfilter rule");
            }

            return Ok(bytes_read);
        }

        if let Some(rule) = parse_append_output_icmp_echo_command(command)? {
            apply_append_rule(rule)?;

            return Ok(bytes_read);
        }

        return_errno_with_message!(Errno::EINVAL, "unsupported netfilter command");
    }
}

enum NetfilterCommand {
    Append(AppendOutputRule),
    AppendNat(AppendNatRule),
    DeleteOutputRule(usize),
    FlushOutput,
    FlushNat(Option<aster_bigtcp::netfilter::NatRuleChain>),
    ZeroOutputCounters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IptablesTable {
    Filter,
    Nat,
}

struct AppendOutputRule {
    protocol: aster_bigtcp::netfilter::OutputRuleProtocol,
    ident: Option<u16>,
    src_addr: Option<aster_bigtcp::wire::Ipv4Address>,
    dst_addr: Option<aster_bigtcp::wire::Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    target: aster_bigtcp::netfilter::OutputRuleTarget,
}

struct AppendNatRule {
    chain: aster_bigtcp::netfilter::NatRuleChain,
    protocol: Option<aster_bigtcp::netfilter::OutputRuleProtocol>,
    src_addr: Option<aster_bigtcp::wire::Ipv4Address>,
    dst_addr: Option<aster_bigtcp::wire::Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    target: aster_bigtcp::netfilter::NatRuleTarget,
    to_addr: Option<aster_bigtcp::wire::Ipv4Address>,
    to_port: Option<u16>,
}

fn apply_command(command: NetfilterCommand) -> Result<()> {
    match command {
        NetfilterCommand::Append(rule) => apply_append_rule(rule),
        NetfilterCommand::AppendNat(rule) => apply_append_nat_rule(rule),
        NetfilterCommand::DeleteOutputRule(index) => {
            if !aster_bigtcp::netfilter::delete_output_rule(index) {
                return_errno_with_message!(Errno::EINVAL, "no such netfilter rule");
            }

            Ok(())
        }
        NetfilterCommand::FlushOutput => {
            aster_bigtcp::netfilter::flush_output_rules();
            Ok(())
        }
        NetfilterCommand::FlushNat(chain) => {
            aster_bigtcp::netfilter::flush_nat_rules(chain);
            Ok(())
        }
        NetfilterCommand::ZeroOutputCounters => {
            aster_bigtcp::netfilter::zero_output_rule_counters();
            Ok(())
        }
    }
}

fn apply_append_rule(rule: AppendOutputRule) -> Result<()> {
    let appended = match rule.protocol {
        aster_bigtcp::netfilter::OutputRuleProtocol::Icmp => {
            aster_bigtcp::netfilter::append_output_icmp_echo_rule(
                rule.ident,
                rule.src_addr,
                rule.dst_addr,
                rule.target,
            )
        }
        aster_bigtcp::netfilter::OutputRuleProtocol::Tcp
        | aster_bigtcp::netfilter::OutputRuleProtocol::Udp => {
            aster_bigtcp::netfilter::append_output_transport_rule(
                rule.protocol,
                rule.src_addr,
                rule.dst_addr,
                rule.src_port,
                rule.dst_port,
                rule.target,
            )
        }
    };

    if !appended {
        return_errno_with_message!(Errno::ENOSPC, "netfilter rule table is full");
    }

    Ok(())
}

fn apply_append_nat_rule(rule: AppendNatRule) -> Result<()> {
    if !aster_bigtcp::netfilter::append_nat_rule(
        rule.chain,
        rule.protocol,
        rule.src_addr,
        rule.dst_addr,
        rule.src_port,
        rule.dst_port,
        rule.target,
        rule.to_addr,
        rule.to_port,
    ) {
        return_errno_with_message!(Errno::ENOSPC, "netfilter NAT rule table is full");
    }

    Ok(())
}

fn parse_iptables_command(command: &str) -> Result<Option<NetfilterCommand>> {
    const PREFIX: &str = "iptables ";

    let Some(rest) = command.strip_prefix(PREFIX) else {
        return Ok(None);
    };

    let mut words = rest.split_whitespace();
    let table = parse_optional_iptables_table(&mut words)?;
    let Some(operation) = words.next() else {
        return_errno_with_message!(Errno::EINVAL, "missing iptables operation");
    };

    // NETFILTER_STAGE21: `-t nat` is parsed here instead of in the userspace
    // shim so direct procfs writes and the shim share the same compatibility
    // boundary.
    match table {
        IptablesTable::Filter => match operation {
            "-A" => parse_iptables_append_command(words).map(NetfilterCommand::Append),
            "-D" => parse_iptables_delete_command(words),
            "-F" => parse_iptables_chain_command(words).map(|_| NetfilterCommand::FlushOutput),
            "-Z" => {
                parse_iptables_chain_command(words).map(|_| NetfilterCommand::ZeroOutputCounters)
            }
            _ => return_errno_with_message!(Errno::EINVAL, "unsupported iptables operation"),
        },
        IptablesTable::Nat => match operation {
            "-A" => parse_iptables_nat_append_command(words).map(NetfilterCommand::AppendNat),
            "-F" => parse_iptables_nat_flush_command(words).map(NetfilterCommand::FlushNat),
            _ => return_errno_with_message!(Errno::EINVAL, "unsupported iptables NAT operation"),
        },
    }
    .map(Some)
}

fn parse_optional_iptables_table(
    words: &mut core::str::SplitWhitespace<'_>,
) -> Result<IptablesTable> {
    let mut cloned_words = words.clone();
    let Some(first_word) = cloned_words.next() else {
        return Ok(IptablesTable::Filter);
    };

    if first_word != "-t" && first_word != "--table" {
        return Ok(IptablesTable::Filter);
    }

    let _ = words.next();
    let Some(table_name) = words.next() else {
        return_errno_with_message!(Errno::EINVAL, "missing iptables table name");
    };

    match table_name {
        "filter" => Ok(IptablesTable::Filter),
        "nat" => Ok(IptablesTable::Nat),
        _ => return_errno_with_message!(Errno::EINVAL, "unsupported iptables table"),
    }
}

fn parse_iptables_append_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<AppendOutputRule> {
    parse_output_chain(&mut words)?;

    let mut protocol = None;
    let mut echo_request = false;
    let mut ident = None;
    let mut src_addr = None;
    let mut dst_addr = None;
    let mut src_port = None;
    let mut dst_port = None;
    let mut target = None;

    while let Some(word) = words.next() {
        match word {
            "-p" => {
                let Some(protocol_name) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing iptables protocol");
                };
                protocol = Some(parse_rule_protocol(protocol_name)?);
            }
            "-m" => {
                let Some(module) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing iptables module");
                };
                if module != "icmp" && module != "tcp" && module != "udp" {
                    return_errno_with_message!(Errno::EINVAL, "unsupported iptables module");
                }
            }
            "-s" | "--source" => {
                let Some(addr) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing source IPv4 address");
                };
                src_addr = Some(parse_ipv4_addr(addr)?);
            }
            "-d" | "--destination" => {
                let Some(addr) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing destination IPv4 address");
                };
                dst_addr = Some(parse_ipv4_addr(addr)?);
            }
            "--icmp-type" => {
                let Some(icmp_type) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing ICMP type");
                };
                if icmp_type != "echo-request" && icmp_type != "8" {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "only ICMP echo-request is supported"
                    );
                }
                echo_request = true;
            }
            "--icmp-id" | "--icmp-echo-ident" => {
                let Some(value) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing ICMP Echo identifier");
                };
                ident = Some(parse_hex_u16(value)?);
            }
            "--sport" | "--source-port" => {
                let Some(value) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing source port");
                };
                src_port = Some(parse_u16(value)?);
            }
            "--dport" | "--destination-port" => {
                let Some(value) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing destination port");
                };
                dst_port = Some(parse_u16(value)?);
            }
            "-j" | "--jump" => {
                let Some(value) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing iptables target");
                };
                target = Some(parse_rule_target(value)?);
            }
            _ => return_errno_with_message!(Errno::EINVAL, "unsupported iptables matcher"),
        }
    }

    let Some(target) = target else {
        return_errno_with_message!(Errno::EINVAL, "missing iptables target");
    };
    let Some(protocol) = protocol else {
        return_errno_with_message!(Errno::EINVAL, "missing iptables protocol");
    };

    match protocol {
        aster_bigtcp::netfilter::OutputRuleProtocol::Icmp => {
            if !echo_request {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "iptables command must match ICMP echo-request"
                );
            }
            if src_port.is_some() || dst_port.is_some() {
                return_errno_with_message!(Errno::EINVAL, "ICMP rules cannot match ports");
            }
        }
        aster_bigtcp::netfilter::OutputRuleProtocol::Tcp
        | aster_bigtcp::netfilter::OutputRuleProtocol::Udp => {
            if echo_request || ident.is_some() {
                return_errno_with_message!(Errno::EINVAL, "transport rules cannot match ICMP");
            }
        }
    }

    Ok(AppendOutputRule {
        protocol,
        ident,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        target,
    })
}

