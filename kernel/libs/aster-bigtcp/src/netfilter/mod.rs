// SPDX-License-Identifier: MPL-2.0

//! Minimal netfilter-like packet hook framework.
//!
//! NETFILTER_STAGE7: This module intentionally starts as a no-op framework.
//! It gives the IPv4 data path stable hook points first, while later stages can
//! add rule tables, matchers, and NAT actions without reshaping `iface::poll`.

mod chain;
mod hook;
mod rule;
mod table;

pub use hook::{
    HookPoint, Ipv4PacketContext, Verdict, evaluate_ipv4, evaluate_ipv4_icmpv4, evaluate_ipv4_tcp,
    evaluate_ipv4_udp,
};
pub use table::{
    ConntrackState, NatRuleChain, NatRuleTarget, OutputRuleProtocol, OutputRuleTarget, append_nat_rule,
    append_filter_icmp_echo_rule, append_filter_transport_rule, append_output_icmp_echo_rule,
    append_output_transport_rule, delete_filter_rule, delete_output_rule, flush_filter_rules,
    delete_nat_rule, flush_nat_rules, flush_output_rules, insert_filter_icmp_echo_rule,
    insert_nat_rule,
    insert_filter_transport_rule, rewrite_ipv4_icmp_postrouting,
    rewrite_ipv4_tcp_postrouting, rewrite_ipv4_udp_postrouting,
    rewrite_forwarded_ipv4_postrouting, rewrite_forwarded_ipv4_prerouting,
    set_filter_chain_policy, write_filter_table_snapshot, zero_filter_rule_counters,
    zero_nat_rule_counters,
    zero_output_rule_counters,
};
