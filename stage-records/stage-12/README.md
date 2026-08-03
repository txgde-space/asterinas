# Stage 12 — IPv6 conntrack and NAT66

Stage 12 completes the core IPv6 packet-path work with a bounded NAT66 table.
The implementation supports address-only `SNAT`, `MASQUERADE`, and `DNAT` for
ICMPv6, TCP, and UDP, including reverse mapping from a fixed-size conntrack
table and transport-checksum repair after an IPv6 address rewrite.

The supported procfs command subset is:

```text
ip6tables -t nat -A PREROUTING|POSTROUTING ... -j DNAT|SNAT|MASQUERADE
ip6tables -t nat -F [PREROUTING|POSTROUTING]
ip6tables -t nat -Z
```

Rules and connection counts are visible in `/proc/netfilter_rules` under
`table nat6`.  Port translation, extension-header chains, NAT64, and dynamic
timeouts are intentionally outside this minimal acceptance stage.

Acceptance scenarios:

```text
test-ipv6-snat   # boot with netfilter.stage12_ipv6_snat=on
test-ipv6-dnat   # boot with netfilter.stage12_ipv6_dnat=on
```
