// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{FileOps, ProcFileBuilder},
        vfs::inode::Inode,
    },
    prelude::*,
    process::{
        credentials::capabilities::CapSet,
        posix_thread::AsPosixThread,
    },
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

        check_netfilter_admin()?;

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
            aster_bigtcp::netfilter::flush_filter_rules(
                aster_bigtcp::netfilter::HookPoint::LocalOut,
            );
            return Ok(bytes_read);
        }

        if command == "zero OUTPUT" {
            aster_bigtcp::netfilter::zero_filter_rule_counters(
                aster_bigtcp::netfilter::HookPoint::LocalOut,
            );
            return Ok(bytes_read);
        }

        if let Some(index) = parse_delete_output_command(command)? {
            if !aster_bigtcp::netfilter::delete_filter_rule(index.0, index.1) {
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
    Insert(AppendOutputRule, usize),
    Check(AppendOutputRule),
    Replace(AppendOutputRule, usize),
    AppendNat(AppendNatRule),
    InsertNat(AppendNatRule, usize),
    CheckNat(AppendNatRule),
    ReplaceNat(AppendNatRule, usize),
    DeleteOutputRule(aster_bigtcp::netfilter::HookPoint, usize),
    DeleteNatRule(aster_bigtcp::netfilter::NatRuleChain, usize),
    FlushOutput(aster_bigtcp::netfilter::HookPoint),
    FlushNat(Option<aster_bigtcp::netfilter::NatRuleChain>),
    SetFilterPolicy(
        aster_bigtcp::netfilter::HookPoint,
        aster_bigtcp::netfilter::OutputRuleTarget,
    ),
    ZeroOutputCounters(aster_bigtcp::netfilter::HookPoint),
    ZeroNatCounters(Option<aster_bigtcp::netfilter::NatRuleChain>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IptablesTable {
    Filter,
    Nat,
}

struct AppendOutputRule {
    chain: aster_bigtcp::netfilter::HookPoint,
    protocol: aster_bigtcp::netfilter::OutputRuleProtocol,
    ident: Option<u16>,
    src_addr: Option<aster_bigtcp::wire::Ipv4Address>,
    dst_addr: Option<aster_bigtcp::wire::Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    conntrack_state: Option<aster_bigtcp::netfilter::ConntrackState>,
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
        NetfilterCommand::Insert(rule, index) => apply_insert_rule(rule, index),
        NetfilterCommand::Check(rule) => apply_check_rule(rule),
        NetfilterCommand::Replace(rule, index) => apply_replace_rule(rule, index),
        NetfilterCommand::AppendNat(rule) => apply_append_nat_rule(rule),
        NetfilterCommand::InsertNat(rule, index) => apply_insert_nat_rule(rule, index),
        NetfilterCommand::CheckNat(rule) => apply_check_nat_rule(rule),
        NetfilterCommand::ReplaceNat(rule, index) => apply_replace_nat_rule(rule, index),
        NetfilterCommand::DeleteOutputRule(chain, index) => {
            if !aster_bigtcp::netfilter::delete_filter_rule(chain, index) {
                return_errno_with_message!(Errno::EINVAL, "no such netfilter rule");
            }

            Ok(())
        }
        NetfilterCommand::FlushOutput(chain) => {
            aster_bigtcp::netfilter::flush_filter_rules(chain);
            Ok(())
        }
        NetfilterCommand::FlushNat(chain) => {
            aster_bigtcp::netfilter::flush_nat_rules(chain);
            Ok(())
        }
        NetfilterCommand::DeleteNatRule(chain, index) => {
            if !aster_bigtcp::netfilter::delete_nat_rule(chain, index) {
                return_errno_with_message!(Errno::EINVAL, "no such NAT rule");
            }

            Ok(())
        }
        NetfilterCommand::SetFilterPolicy(chain, target) => {
            aster_bigtcp::netfilter::set_filter_chain_policy(chain, target);
            Ok(())
        }
        NetfilterCommand::ZeroOutputCounters(chain) => {
            aster_bigtcp::netfilter::zero_filter_rule_counters(chain);
            Ok(())
        }
        NetfilterCommand::ZeroNatCounters(chain) => {
            aster_bigtcp::netfilter::zero_nat_rule_counters(chain);
            Ok(())
        }
    }
}

fn apply_append_rule(rule: AppendOutputRule) -> Result<()> {
    let appended = match rule.protocol {
        aster_bigtcp::netfilter::OutputRuleProtocol::Icmp => {
            aster_bigtcp::netfilter::append_filter_icmp_echo_rule(
                rule.chain,
                rule.ident,
                rule.src_addr,
                rule.dst_addr,
                rule.target,
            )
        }
        aster_bigtcp::netfilter::OutputRuleProtocol::Tcp
        | aster_bigtcp::netfilter::OutputRuleProtocol::Udp => {
            aster_bigtcp::netfilter::append_filter_transport_rule(
                rule.chain,
                rule.protocol,
                rule.src_addr,
                rule.dst_addr,
                rule.src_port,
                rule.dst_port,
                rule.conntrack_state,
                rule.target,
            )
        }
    };

    if !appended {
        return_errno_with_message!(Errno::ENOSPC, "netfilter rule table is full");
    }

    Ok(())
}

fn apply_insert_rule(rule: AppendOutputRule, index: usize) -> Result<()> {
    let inserted = match rule.protocol {
        aster_bigtcp::netfilter::OutputRuleProtocol::Icmp => {
            aster_bigtcp::netfilter::insert_filter_icmp_echo_rule(
                rule.chain,
                index,
                rule.ident,
                rule.src_addr,
                rule.dst_addr,
                rule.target,
            )
        }
        aster_bigtcp::netfilter::OutputRuleProtocol::Tcp
        | aster_bigtcp::netfilter::OutputRuleProtocol::Udp => {
            aster_bigtcp::netfilter::insert_filter_transport_rule(
                rule.chain,
                index,
                rule.protocol,
                rule.src_addr,
                rule.dst_addr,
                rule.src_port,
                rule.dst_port,
                rule.conntrack_state,
                rule.target,
            )
        }
    };

    if !inserted {
        return_errno_with_message!(Errno::ENOSPC, "netfilter rule table is full or index is invalid");
    }

    Ok(())
}

fn apply_check_rule(rule: AppendOutputRule) -> Result<()> {
    let matches = match rule.protocol {
        aster_bigtcp::netfilter::OutputRuleProtocol::Icmp => {
            aster_bigtcp::netfilter::check_filter_icmp_echo_rule(
                rule.chain,
                rule.ident,
                rule.src_addr,
                rule.dst_addr,
                rule.target,
            )
        }
        aster_bigtcp::netfilter::OutputRuleProtocol::Tcp
        | aster_bigtcp::netfilter::OutputRuleProtocol::Udp => {
            aster_bigtcp::netfilter::check_filter_transport_rule(
                rule.chain,
                rule.protocol,
                rule.src_addr,
                rule.dst_addr,
                rule.src_port,
                rule.dst_port,
                rule.conntrack_state,
                rule.target,
            )
        }
    };

    if !matches {
        return_errno_with_message!(Errno::EINVAL, "no matching netfilter rule");
    }

    Ok(())
}

fn apply_replace_rule(rule: AppendOutputRule, index: usize) -> Result<()> {
    let replaced = match rule.protocol {
        aster_bigtcp::netfilter::OutputRuleProtocol::Icmp => {
            aster_bigtcp::netfilter::replace_filter_icmp_echo_rule(
                rule.chain,
                index,
                rule.ident,
                rule.src_addr,
                rule.dst_addr,
                rule.target,
            )
        }
        aster_bigtcp::netfilter::OutputRuleProtocol::Tcp
        | aster_bigtcp::netfilter::OutputRuleProtocol::Udp => {
            aster_bigtcp::netfilter::replace_filter_transport_rule(
                rule.chain,
                index,
                rule.protocol,
                rule.src_addr,
                rule.dst_addr,
                rule.src_port,
                rule.dst_port,
                rule.conntrack_state,
                rule.target,
            )
        }
    };

    if !replaced {
        return_errno_with_message!(Errno::EINVAL, "no such netfilter rule");
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

fn apply_insert_nat_rule(rule: AppendNatRule, index: usize) -> Result<()> {
    if !aster_bigtcp::netfilter::insert_nat_rule(
        rule.chain,
        index,
        rule.protocol,
        rule.src_addr,
        rule.dst_addr,
        rule.src_port,
        rule.dst_port,
        rule.target,
        rule.to_addr,
        rule.to_port,
    ) {
        return_errno_with_message!(
            Errno::ENOSPC,
            "netfilter NAT rule table is full or index is invalid"
        );
    }

    Ok(())
}

fn apply_check_nat_rule(rule: AppendNatRule) -> Result<()> {
    if !aster_bigtcp::netfilter::check_nat_rule(
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
        return_errno_with_message!(Errno::EINVAL, "no matching NAT rule");
    }

    Ok(())
}

fn apply_replace_nat_rule(rule: AppendNatRule, index: usize) -> Result<()> {
    if !aster_bigtcp::netfilter::replace_nat_rule(
        rule.chain,
        index,
        rule.protocol,
        rule.src_addr,
        rule.dst_addr,
        rule.src_port,
        rule.dst_port,
        rule.target,
        rule.to_addr,
        rule.to_port,
    ) {
        return_errno_with_message!(Errno::EINVAL, "no such NAT rule");
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
            "-I" => parse_iptables_insert_command(words)
                .map(|(rule, index)| NetfilterCommand::Insert(rule, index)),
            "-C" => parse_iptables_append_command(words).map(NetfilterCommand::Check),
            "-R" => parse_iptables_replace_command(words)
                .map(|(rule, index)| NetfilterCommand::Replace(rule, index)),
            "-D" => parse_iptables_delete_command(words),
            "-F" => parse_iptables_chain_command(words).map(NetfilterCommand::FlushOutput),
            "-P" => parse_iptables_policy_command(words),
            "-Z" => {
                parse_iptables_chain_command(words).map(NetfilterCommand::ZeroOutputCounters)
            }
            _ => return_errno_with_message!(Errno::EINVAL, "unsupported iptables operation"),
        },
        IptablesTable::Nat => match operation {
            "-A" => parse_iptables_nat_append_command(words).map(NetfilterCommand::AppendNat),
            "-I" => parse_iptables_nat_insert_command(words)
                .map(|(rule, index)| NetfilterCommand::InsertNat(rule, index)),
            "-C" => parse_iptables_nat_append_command(words).map(NetfilterCommand::CheckNat),
            "-R" => parse_iptables_nat_replace_command(words)
                .map(|(rule, index)| NetfilterCommand::ReplaceNat(rule, index)),
            "-D" => parse_iptables_nat_delete_command(words),
            "-F" => parse_iptables_nat_flush_command(words).map(NetfilterCommand::FlushNat),
            "-Z" => parse_iptables_nat_flush_command(words).map(NetfilterCommand::ZeroNatCounters),
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
    let chain = parse_filter_chain(&mut words)?;

    parse_iptables_filter_rule(chain, words)
}

fn parse_iptables_insert_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<(AppendOutputRule, usize)> {
    let chain = parse_filter_chain(&mut words)?;
    let index = match words.clone().next() {
        Some(value) if !value.starts_with('-') => {
            let _ = words.next();
            let one_based = value
                .parse::<usize>()
                .map_err(|_| Error::with_message(Errno::EINVAL, "invalid iptables insert position"))?;
            if one_based == 0 {
                return_errno_with_message!(Errno::EINVAL, "iptables insert position is one-based");
            }
            one_based - 1
        }
        _ => 0,
    };

    parse_iptables_filter_rule(chain, words).map(|rule| (rule, index))
}

fn parse_iptables_replace_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<(AppendOutputRule, usize)> {
    let chain = parse_filter_chain(&mut words)?;
    let Some(index) = words.next() else {
        return_errno_with_message!(Errno::EINVAL, "missing iptables replace position");
    };
    let index = index
        .parse::<usize>()
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid iptables replace position"))?;
    if index == 0 {
        return_errno_with_message!(Errno::EINVAL, "iptables rule number is one-based");
    }

    parse_iptables_filter_rule(chain, words).map(|rule| (rule, index - 1))
}

fn parse_iptables_filter_rule(
    chain: aster_bigtcp::netfilter::HookPoint,
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<AppendOutputRule> {

    let mut protocol = None;
    let mut echo_request = false;
    let mut ident = None;
    let mut src_addr = None;
    let mut dst_addr = None;
    let mut src_port = None;
    let mut dst_port = None;
    let mut conntrack_module = false;
    let mut conntrack_state = None;
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
                if module == "conntrack" {
                    conntrack_module = true;
                } else if module != "icmp" && module != "tcp" && module != "udp" {
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
            "--ctstate" => {
                let Some(value) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing conntrack state");
                };
                conntrack_state = Some(parse_conntrack_state(value)?);
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
    if conntrack_state.is_some() && !conntrack_module {
        return_errno_with_message!(Errno::EINVAL, "--ctstate requires -m conntrack");
    }

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
            if conntrack_state.is_some() {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "conntrack state matching is currently limited to TCP and UDP"
                );
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
        chain,
        protocol,
        ident,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        conntrack_state,
        target,
    })
}

fn parse_iptables_policy_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<NetfilterCommand> {
    let chain = parse_filter_chain(&mut words)?;
    let Some(target) = words.next() else {
        return_errno_with_message!(Errno::EINVAL, "missing iptables chain policy");
    };
    if words.next().is_some() {
        return_errno_with_message!(Errno::EINVAL, "trailing iptables policy tokens");
    }

    Ok(NetfilterCommand::SetFilterPolicy(chain, parse_rule_target(target)?))
}

fn parse_iptables_nat_append_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<AppendNatRule> {
    let chain = parse_nat_chain(&mut words)?;
    parse_iptables_nat_rule(chain, words)
}

fn parse_iptables_nat_insert_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<(AppendNatRule, usize)> {
    let chain = parse_nat_chain(&mut words)?;
    let index = match words.clone().next() {
        Some(value) if !value.starts_with('-') => {
            let _ = words.next();
            let one_based = value
                .parse::<usize>()
                .map_err(|_| Error::with_message(Errno::EINVAL, "invalid NAT insert position"))?;
            if one_based == 0 {
                return_errno_with_message!(Errno::EINVAL, "NAT insert position is one-based");
            }
            one_based - 1
        }
        _ => 0,
    };

    parse_iptables_nat_rule(chain, words).map(|rule| (rule, index))
}

fn parse_iptables_nat_replace_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<(AppendNatRule, usize)> {
    let chain = parse_nat_chain(&mut words)?;
    let Some(index) = words.next() else {
        return_errno_with_message!(Errno::EINVAL, "missing NAT replace position");
    };
    let index = index
        .parse::<usize>()
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid NAT replace position"))?;
    if index == 0 {
        return_errno_with_message!(Errno::EINVAL, "NAT rule number is one-based");
    }

    parse_iptables_nat_rule(chain, words).map(|rule| (rule, index - 1))
}

fn parse_iptables_nat_rule(
    chain: aster_bigtcp::netfilter::NatRuleChain,
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<AppendNatRule> {
    let mut protocol = None;
    let mut src_addr = None;
    let mut dst_addr = None;
    let mut src_port = None;
    let mut dst_port = None;
    let mut target = None;
    let mut to_addr = None;
    let mut to_port = None;

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
                if module != "tcp" && module != "udp" && module != "icmp" {
                    return_errno_with_message!(Errno::EINVAL, "unsupported NAT matcher module");
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
                    return_errno_with_message!(Errno::EINVAL, "missing NAT target");
                };
                target = Some(parse_nat_target(value)?);
            }
            "--to-source" | "--to-destination" => {
                let Some(value) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing NAT translation address");
                };
                let (addr, port) = parse_nat_to_addr_port(value)?;
                to_addr = Some(addr);
                to_port = port;
            }
            _ => return_errno_with_message!(Errno::EINVAL, "unsupported NAT matcher"),
        }
    }

    let Some(target) = target else {
        return_errno_with_message!(Errno::EINVAL, "missing NAT target");
    };

    validate_nat_rule(chain, target, to_addr, src_port, dst_port)?;

    Ok(AppendNatRule {
        chain,
        protocol,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        target,
        to_addr,
        to_port,
    })
}

fn parse_iptables_nat_delete_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<NetfilterCommand> {
    let chain = parse_nat_chain(&mut words)?;
    let Some(index) = words.next() else {
        return_errno_with_message!(Errno::EINVAL, "missing NAT rule number");
    };
    if words.next().is_some() {
        return_errno_with_message!(Errno::EINVAL, "trailing NAT delete tokens");
    }

    let index = index
        .parse::<usize>()
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid NAT rule number"))?;
    if index == 0 {
        return_errno_with_message!(Errno::EINVAL, "NAT rule number is one-based");
    }

    Ok(NetfilterCommand::DeleteNatRule(chain, index - 1))
}

fn parse_iptables_delete_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<NetfilterCommand> {
    let chain = parse_filter_chain(&mut words)?;
    let Some(index) = words.next() else {
        return_errno_with_message!(Errno::EINVAL, "missing iptables rule number");
    };
    if words.next().is_some() {
        return_errno_with_message!(Errno::EINVAL, "trailing iptables delete tokens");
    }

    let index = index
        .parse::<usize>()
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid iptables rule number"))?;
    if index == 0 {
        return_errno_with_message!(Errno::EINVAL, "iptables rule number is one-based");
    }

    Ok(NetfilterCommand::DeleteOutputRule(chain, index - 1))
}

fn check_netfilter_admin() -> Result<()> {
    let thread = current_thread!();
    let posix_thread = thread
        .as_posix_thread()
        .ok_or_else(|| Error::with_message(Errno::EPERM, "netfilter requires a POSIX thread"))?;
    let credentials = posix_thread.credentials();

    if credentials.euid().is_root()
        || credentials
            .effective_capset()
            .contains(CapSet::NET_ADMIN)
    {
        return Ok(());
    }

    return_errno_with_message!(Errno::EPERM, "netfilter requires CAP_NET_ADMIN");
}

fn parse_iptables_chain_command(mut words: core::str::SplitWhitespace<'_>) -> Result<aster_bigtcp::netfilter::HookPoint> {
    let chain = parse_filter_chain(&mut words)?;
    if words.next().is_some() {
        return_errno_with_message!(Errno::EINVAL, "trailing iptables chain command tokens");
    }

    Ok(chain)
}

fn parse_iptables_nat_flush_command(
    mut words: core::str::SplitWhitespace<'_>,
) -> Result<Option<aster_bigtcp::netfilter::NatRuleChain>> {
    let Some(chain_name) = words.next() else {
        return Ok(None);
    };

    let chain = parse_nat_chain_name(chain_name)?;
    if words.next().is_some() {
        return_errno_with_message!(Errno::EINVAL, "trailing NAT flush tokens");
    }

    Ok(Some(chain))
}

fn parse_filter_chain(words: &mut core::str::SplitWhitespace<'_>) -> Result<aster_bigtcp::netfilter::HookPoint> {
    let Some(chain) = words.next() else {
        return_errno_with_message!(Errno::EINVAL, "missing iptables chain");
    };

    match chain {
        "INPUT" => Ok(aster_bigtcp::netfilter::HookPoint::LocalIn),
        "FORWARD" => Ok(aster_bigtcp::netfilter::HookPoint::Forward),
        "OUTPUT" => Ok(aster_bigtcp::netfilter::HookPoint::LocalOut),
        _ => return_errno_with_message!(Errno::EINVAL, "unsupported filter chain"),
    }
}

fn parse_nat_chain(
    words: &mut core::str::SplitWhitespace<'_>,
) -> Result<aster_bigtcp::netfilter::NatRuleChain> {
    let Some(chain) = words.next() else {
        return_errno_with_message!(Errno::EINVAL, "missing NAT chain");
    };

    parse_nat_chain_name(chain)
}

fn parse_nat_chain_name(chain: &str) -> Result<aster_bigtcp::netfilter::NatRuleChain> {
    match chain {
        "PREROUTING" => Ok(aster_bigtcp::netfilter::NatRuleChain::PreRouting),
        "POSTROUTING" => Ok(aster_bigtcp::netfilter::NatRuleChain::PostRouting),
        _ => return_errno_with_message!(Errno::EINVAL, "unsupported NAT chain"),
    }
}

fn parse_append_output_icmp_echo_command(command: &str) -> Result<Option<AppendOutputRule>> {
    const PREFIX: &str = "append OUTPUT ";

    let Some(rest) = command.strip_prefix(PREFIX) else {
        return Ok(None);
    };

    parse_append_output_rule(rest).map(Some)
}

fn parse_append_output_rule(command: &str) -> Result<AppendOutputRule> {
    let mut words = command.split_whitespace();
    let mut src_addr = None;
    let mut dst_addr = None;

    loop {
        let Some(word) = words.next() else {
            return_errno_with_message!(Errno::EINVAL, "missing icmp matcher");
        };

        match word {
            "src" => {
                let Some(addr) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing source IPv4 address");
                };
                src_addr = Some(parse_ipv4_addr(addr)?);
            }
            "dst" => {
                let Some(addr) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing destination IPv4 address");
                };
                dst_addr = Some(parse_ipv4_addr(addr)?);
            }
            "icmp-echo-ident" => {
                let Some(ident) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing ICMP Echo identifier");
                };
                let Some(target) = words.next() else {
                    return_errno_with_message!(Errno::EINVAL, "missing target");
                };
                if words.next().is_some() {
                    return_errno_with_message!(Errno::EINVAL, "trailing append command tokens");
                }

                return Ok(AppendOutputRule {
                    chain: aster_bigtcp::netfilter::HookPoint::LocalOut,
                    protocol: aster_bigtcp::netfilter::OutputRuleProtocol::Icmp,
                    ident: Some(parse_hex_u16(ident)?),
                    src_addr,
                    dst_addr,
                    src_port: None,
                    dst_port: None,
                    conntrack_state: None,
                    target: parse_rule_target(target)?,
                });
            }
            _ => return_errno_with_message!(Errno::EINVAL, "unsupported append matcher"),
        }
    }
}

fn parse_delete_output_command(
    command: &str,
) -> Result<Option<(aster_bigtcp::netfilter::HookPoint, usize)>> {
    const PREFIX: &str = "delete OUTPUT ";

    let Some(index) = command.strip_prefix(PREFIX) else {
        return Ok(None);
    };

    index
        .parse::<usize>()
        .map(|index| Some((aster_bigtcp::netfilter::HookPoint::LocalOut, index)))
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid delete index"))
}

fn parse_hex_u16(value: &str) -> Result<u16> {
    let Some(value) = value.strip_prefix("0x") else {
        return_errno_with_message!(Errno::EINVAL, "hex value must use 0x prefix");
    };

    u16::from_str_radix(value, 16)
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid u16 hex value"))
}

fn parse_u16(value: &str) -> Result<u16> {
    if let Some(value) = value.strip_prefix("0x") {
        return u16::from_str_radix(value, 16)
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid u16 hex value"));
    }

    value
        .parse::<u16>()
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid u16 value"))
}

fn parse_rule_protocol(value: &str) -> Result<aster_bigtcp::netfilter::OutputRuleProtocol> {
    match value {
        "icmp" => Ok(aster_bigtcp::netfilter::OutputRuleProtocol::Icmp),
        "tcp" => Ok(aster_bigtcp::netfilter::OutputRuleProtocol::Tcp),
        "udp" => Ok(aster_bigtcp::netfilter::OutputRuleProtocol::Udp),
        _ => return_errno_with_message!(Errno::EINVAL, "unsupported iptables protocol"),
    }
}

fn parse_conntrack_state(value: &str) -> Result<aster_bigtcp::netfilter::ConntrackState> {
    match value {
        "NEW" => Ok(aster_bigtcp::netfilter::ConntrackState::New),
        "ESTABLISHED" => Ok(aster_bigtcp::netfilter::ConntrackState::Established),
        _ => return_errno_with_message!(
            Errno::EINVAL,
            "only conntrack states NEW and ESTABLISHED are supported"
        ),
    }
}

fn parse_nat_target(value: &str) -> Result<aster_bigtcp::netfilter::NatRuleTarget> {
    match value {
        "DNAT" => Ok(aster_bigtcp::netfilter::NatRuleTarget::Dnat),
        "MASQUERADE" => Ok(aster_bigtcp::netfilter::NatRuleTarget::Masquerade),
        "SNAT" => Ok(aster_bigtcp::netfilter::NatRuleTarget::Snat),
        _ => return_errno_with_message!(Errno::EINVAL, "unsupported NAT target"),
    }
}

fn parse_nat_to_addr_port(value: &str) -> Result<(aster_bigtcp::wire::Ipv4Address, Option<u16>)> {
    let (addr, port) = value.split_once(':').unwrap_or((value, ""));
    let port = if port.is_empty() {
        None
    } else {
        Some(parse_u16(port)?)
    };

    Ok((parse_ipv4_addr(addr)?, port))
}

fn validate_nat_rule(
    chain: aster_bigtcp::netfilter::NatRuleChain,
    target: aster_bigtcp::netfilter::NatRuleTarget,
    to_addr: Option<aster_bigtcp::wire::Ipv4Address>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
) -> Result<()> {
    match target {
        aster_bigtcp::netfilter::NatRuleTarget::Dnat => {
            if chain != aster_bigtcp::netfilter::NatRuleChain::PreRouting {
                return_errno_with_message!(Errno::EINVAL, "DNAT requires PREROUTING");
            }
            if to_addr.is_none() {
                return_errno_with_message!(Errno::EINVAL, "DNAT requires --to-destination");
            }
        }
        aster_bigtcp::netfilter::NatRuleTarget::Snat => {
            if chain != aster_bigtcp::netfilter::NatRuleChain::PostRouting {
                return_errno_with_message!(Errno::EINVAL, "SNAT requires POSTROUTING");
            }
            if to_addr.is_none() {
                return_errno_with_message!(Errno::EINVAL, "SNAT requires --to-source");
            }
        }
        aster_bigtcp::netfilter::NatRuleTarget::Masquerade => {
            if chain != aster_bigtcp::netfilter::NatRuleChain::PostRouting {
                return_errno_with_message!(Errno::EINVAL, "MASQUERADE requires POSTROUTING");
            }
            if to_addr.is_some() || src_port.is_some() || dst_port.is_some() {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "MASQUERADE translation address and port matchers are unsupported"
                );
            }
        }
    }

    Ok(())
}

fn parse_rule_target(value: &str) -> Result<aster_bigtcp::netfilter::OutputRuleTarget> {
    match value {
        "ACCEPT" => Ok(aster_bigtcp::netfilter::OutputRuleTarget::Accept),
        "DROP" => Ok(aster_bigtcp::netfilter::OutputRuleTarget::Drop),
        _ => return_errno_with_message!(Errno::EINVAL, "unsupported netfilter target"),
    }
}

fn parse_ipv4_addr(value: &str) -> Result<aster_bigtcp::wire::Ipv4Address> {
    let mut octets = [0u8; 4];
    let (value, prefix_len) = value.split_once('/').unwrap_or((value, "32"));
    if prefix_len != "32" {
        return_errno_with_message!(Errno::EINVAL, "only IPv4 /32 matchers are supported");
    }

    let mut parts = value.split('.');

    for octet in &mut octets {
        let Some(part) = parts.next() else {
            return_errno_with_message!(Errno::EINVAL, "IPv4 address has too few octets");
        };
        *octet = part
            .parse::<u8>()
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid IPv4 octet"))?;
    }

    if parts.next().is_some() {
        return_errno_with_message!(Errno::EINVAL, "IPv4 address has too many octets");
    }

    Ok(aster_bigtcp::wire::Ipv4Address::new(
        octets[0], octets[1], octets[2], octets[3],
    ))
}
