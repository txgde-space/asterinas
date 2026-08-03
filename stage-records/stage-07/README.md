# Stage 7 - Mutable NAT rule lifecycle

Stage 7 extends the Stage 6 netfilter control plane with the smallest useful
mutable NAT workflow:

- `iptables -t nat -I CHAIN [POSITION] ...` inserts a rule using one-based,
  per-chain numbering;
- `iptables -t nat -D CHAIN POSITION` deletes a rule using the same numbering;
- `iptables -t nat -Z [CHAIN]` clears packet and byte counters;
- `/proc/netfilter_rules` prints independent PREROUTING and POSTROUTING rule
  numbers and chain counts.

The implementation remains intentionally bounded: only the built-in NAT
chains are supported, there are no user-defined chains, NAT policies remain
`ACCEPT`, and rule changes reset active conntrack/NAT mappings to avoid stale
translations after a control-plane update.

## Acceptance evidence

The initramfs regression `run_userspace_iptables_nat_rule_lifecycle` covers
append, insert-at-one, per-chain snapshot numbering, `-Z`, per-chain `-D`, and
full-table flush. Existing ICMP/TCP/UDP NAT and full regression tests must also
remain green.

Record the command output under `stage-records/stage-07/` and archive it in
the Windows shared folder before committing.
