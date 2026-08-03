# Stage 2 Bug and Fix Ledger

This ledger is append-only evidence for defects found while developing Stage 2.
Each entry links the failure evidence to a concrete patch and records whether
the repair has been validated. A fix is never described as passed before its
targeted runtime test succeeds.

| ID | Trigger and symptom | Root cause | Repair | Status |
|---|---|---|---|---|
| S2B-001 | First forwarding-pipeline build failed with missing `VecDeque`, missing `E: Ext`, and invalid `Ipv4Repr` serialization errors. | The new egress queue lacked an import and trait bound; raw output bypassed the `Ipv4Packet` serializer. | `netfilter-stage-02b-forwarding-fix-01.patch` | Fixed; later build and regression passed. |
| S2B-002 | Second forwarding-pipeline build failed because `println` was unavailable and `Ipv4Addr.0` did not exist. | Kernel prelude and address representation assumptions were incomplete. | `netfilter-stage-02b-forwarding-fix-02.patch` | Fixed; later build and regression passed. |
| S2C-001 | First real TAP endpoint ping triggered a kernel panic: `range end index 84 out of range for slice of length 20`. Stack trace reaches `EtherIface::emit_forwarded_ip` through `router::forward_ipv4_packet`. | The forwarding path allocated only `Ipv4Repr::buffer_len()` (the 20-byte IPv4 header), then emitted a datagram whose header declared an 84-byte total length and accessed its transport payload. | Add `ForwardedIpv4Packet::buffer_len()` and use it for Ether/IP forwarded transmission: `netfilter-stage-02c-forwarding-buffer-fix-01.patch`. | Passed: the targeted rerun had no panic and both directions reached 4/4, 0% loss. |
| S2C-002 | The buffer-fix rerun forwarded packets in both directions, but left-to-right ICMP lost its first two packets (2/4 received). | The Ethernet egress path used its transmit token to emit an ARP request, but the already-dequeued forwarded packet was not retained for the subsequent ARP reply. Only later ICMP retransmissions succeeded. | Make the egress dispatch report whether it consumed the routed packet; requeue ARP-pending packets at the head of the bounded forwarding queue, and require 0% loss in the TAP acceptance script: `netfilter-stage-02c-arp-pending-queue-fix-02.patch`. | Passed: targeted rerun reached 4/4, 0% loss in both directions. |

## S2C-001 evidence

- Raw failure log: `router-tap-attempt-01-panic.log`
- Raw-log SHA-256: `5a1b38d261cb82cc8d8cf692122620326f1922f2cf3979801afed9558c06ed52`
- Trigger: host namespace `as2left` pinged `10.0.3.2` through the two-TAP
  topology while `netfilter.ipv4_forward=on`.
- Build reached the optimized release profile in 1m 15s; the failure occurred
  at guest runtime, around 41.310 seconds after boot.
- Repair patch SHA-256:
  `e7b68842af3dbd8ea39f21f75019bdc4c3ae6c3d062cbb501898b24c77dba018`.
- Repair locations:
  `kernel/libs/aster-bigtcp/src/forwarding.rs`,
  `kernel/libs/aster-bigtcp/src/iface/phy/ether.rs`, and
  `kernel/libs/aster-bigtcp/src/iface/phy/ip.rs`.

The final targeted rerun reached bidirectional ICMP forwarding without an
`Uncaught panic`: both directions received 4 of 4 packets with 0% loss, and
TTL 63 proves one forwarding hop. The raw VMware logs remain in the user's
Stage 2 evidence archive pending import; their console results are recorded
here without fabricating local raw-log hashes.
