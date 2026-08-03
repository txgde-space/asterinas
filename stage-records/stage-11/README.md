# Stage 11 — IPv6 netfilter filtering

Stage 11 adds a bounded IPv6 filter table alongside the existing IPv4 table.
It evaluates INPUT and FORWARD hooks before ICMPv6/NDP or forwarding, keeps
per-rule packet/byte counters, renders the rules through `/proc/netfilter_rules`,
and exposes a boot-time acceptance rule for an IPv6 ICMPv6 FORWARD DROP test.

The supported matcher subset is:

- source and destination IPv6 addresses;
- `all`, ICMPv6, TCP, and UDP next-header selectors;
- ICMPv6 message type;
- ACCEPT/DROP targets and per-chain default policy.

The guest control surface accepts the following bounded `ip6tables` subset via
`/proc/netfilter_rules`: `-A`, `-P`, `-F`, and `-Z` for INPUT/FORWARD/OUTPUT,
with `-p ipv6-icmp|tcp|udp`, `/128` address matchers, ICMPv6 type names or
numbers, and ACCEPT/DROP targets.

This stage intentionally does not claim IPv6 NAT. IPv6 NAT/conntrack is the
final Stage 12 scope, where the state table and rewrite checksum tests will be
added separately.

Acceptance command:

```text
sudo ./tools/net/stage2-router-topology.sh test-ipv6-forward-drop
```

The guest must be booted with:

```text
netfilter.ipv6_forward=on netfilter.stage11_ipv6_forward_drop=on
```
