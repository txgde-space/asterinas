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

