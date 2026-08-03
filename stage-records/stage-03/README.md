# Netfilter Stage 3 — Stateful ICMP NAT and forwarding-policy acceptance

## Status

**Passed on the VMware Ubuntu validation environment (2026-07-30).**

The raw console logs remain in the Ubuntu worktree and should be archived to
the Windows shared folder with the stage archive command recorded in the
project notes.  The results below are derived from the successful console
output captured during validation; no unavailable raw log is represented as an
imported artifact.

## Delivered scope

Stage 3 builds on the Stage 2 forwarding pipeline and provides the first
usable, deliberately bounded netfilter/NAT slice:

- IPv4 `PREROUTING`, `FORWARD`, and `POSTROUTING` processing for forwarded
  traffic.
- Stateful, address-only ICMP NAT mapping and reverse translation.
- ICMP `MASQUERADE`/SNAT at `POSTROUTING`.
- ICMP DNAT at `PREROUTING`, including the reply-path reverse translation.
- Runtime `FORWARD`-chain ICMP `DROP` policy validation.
- NAT is applied at most once when an outbound packet is temporarily retained
  pending ARP resolution.

This is not yet Linux-compatible general-purpose iptables NAT.  In particular,
TCP/UDP port translation, protocol-generic conntrack, connection expiry and
eviction policy, rule-management userspace ABI, and nftables compatibility are
outside this stage.

## Acceptance results

| Scenario | Expected result | Observed result |
| --- | --- | --- |
| ICMP MASQUERADE, left to right | right-side capture sees `10.0.3.15 > 10.0.3.2`; bidirectional reply succeeds | 4/4 replies, 0% loss; capture matched |
| ICMP DNAT to virtual service | right-side capture sees `10.0.2.2 > 10.0.3.2`; reply is reverse-translated | 4/4 replies, 0% loss; capture matched |
| `FORWARD` ICMP `DROP` | no reply reaches the source | 4 transmitted, 0 received; expected drop passed |
| Existing regression suite | no regressions with forwarding enabled | passed |

## Patch provenance

| Artifact | SHA-256 |
| --- | --- |
| `netfilter-stage-03-stateful-icmp-nat.patch` | `17265f654156afebe63bb55ae3c465db2e5666fd18cf416e8fa24b50509a9f6e` |
| `netfilter-stage-03-dnat-forward-filter-acceptance.patch` | `c33724096f7190782e28c8738d039a142c950a3b4eb72eda046d0567085b7044` |

## Evidence preservation

Archive the complete `stage-records` directory, together with the generated
environment manifest, after each stage.  This preserves baseline through
Stage 3 logs, patches, bug records, and the exact local revision for later
technical documentation and presentation work.
