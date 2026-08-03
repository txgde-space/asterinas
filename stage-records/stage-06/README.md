# Stage 6: bounded conntrack state and NAT lifecycle

## Delivered scope

- Adds `iptables -m conntrack --ctstate NEW|ESTABLISHED` for IPv4 TCP and UDP
  filter rules in `INPUT`, `FORWARD`, and `OUTPUT`.
- Retains allocation-free, fixed-capacity NAT state: 64 transport mappings and
  32 ICMP mappings.
- Expires idle mappings using kernel jiffies: ICMP after 30 seconds, UDP after
  60 seconds, TCP `NEW` after 30 seconds, and TCP `ESTABLISHED` after five
  minutes. A later lookup or new allocation reclaims expired slots.
- Promotes a TCP/UDP mapping to `ESTABLISHED` when reverse-direction traffic
  matches its translated tuple.
- Exposes the requested conntrack state in `/proc/netfilter_rules` snapshots.

## Explicit compatibility boundary

This is intentionally not a complete Linux conntrack clone. `RELATED`,
`INVALID`, TCP flag/state validation, helper modules, zones, expectations,
conntrack event notifications, and user-configurable timeouts are not
implemented. ICMP keeps the Stage 3 address-only stateful NAT mapping and is
not accepted by `-m conntrack` in this stage.

## Regression gate

The standard regression adds parser/snapshot coverage for append and insert of
`NEW`/`ESTABLISHED` rules and verifies that `RELATED` is rejected. The TAP
acceptance mode installs a `FORWARD DROP` policy with exactly two exceptions:
an outbound TCP `NEW` rule and an `ESTABLISHED` return-path rule. Therefore a
successful application-level TCP echo proves both state transitions and
policy-based filtering.

Run the full in-guest regression first, then archive its raw log before
committing. Run the TAP acceptance only after the isolated topology is ready.
