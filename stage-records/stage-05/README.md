# Stage 5: Dynamic filter policy and ordered rule control

## Scope

Stage 5 extends the in-guest `iptables` compatibility shim and its
`/proc/netfilter_rules` control plane. It intentionally does **not** claim
compatibility with the Linux `iptables-legacy` socket-option ABI.

Supported filter-table additions:

- `iptables -P|--policy INPUT|FORWARD|OUTPUT ACCEPT|DROP`;
- `iptables -I|--insert CHAIN [RULE_NUMBER] ...` with Linux-style one-based
  rule numbers, defaulting to the head of the chain;
- first-match exceptions before the chain default policy;
- snapshot output that reports each mutable chain's active policy.

The bundled in-initramfs `iptables` shim forwards mutating commands to
`/proc/netfilter_rules`; it is a deliberately bounded compatibility layer,
not the upstream `iptables` binary.

## Acceptance

The regression test `run_userspace_iptables_insert_and_policy` proves:

1. a rule inserted at position 1 overrides an earlier matching DROP rule;
2. an empty OUTPUT chain with policy DROP blocks an ICMP echo request;
3. `-I OUTPUT ... -j ACCEPT` creates an explicit exception that restores the
   request despite policy DROP; and
4. the test restores OUTPUT policy ACCEPT and the existing test-owned default
   rule before it exits.

Run the full default regression after applying this stage. Preserve the raw
log in `stage-records/stage-05/regression-default.log` before creating the
Stage 5 commit.
