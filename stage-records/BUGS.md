# Netfilter Bug and Fix Index

This is the cross-stage, append-only index for defects and verification
failures. Stage-specific ledgers retain the detailed raw evidence. A `Passed`
entry means the named acceptance run succeeded; it does not extend the claimed
feature scope beyond that acceptance.

| ID | Stage | Failure / root cause | Evidence and repair | Validation and commit |
|---|---|---|---|---|
| S1-001 | Stage 1 | The first full regression failed because the legacy address-match test used a 512-byte procfs snapshot. New INPUT and FORWARD listings moved a required line beyond that buffer. | Failure log `stage-01/regression-attempt-01-buffer-truncation.log`; repair `stage-01/netfilter-stage-01-fix-01.patch` increases only the test buffer to 2048 bytes. | Passed in `stage-01/regression-fix-01.log`; `70876a8f6344450cedcf1d674afd1a655b7bab50` (`Add Stage 1 IPv4 filter chains`). |
| S2A-001 | Stage 2A | The first multi-NIC acceptance build failed with Rust `E0282`: the IPv4-address closure parameter had no inferred type. | Failure log `stage-02/multi-nic-attempt-01-build-failure.log`; repair recorded by `stage-02/netfilter-stage-02a-check-fix-01.patch`, adding the explicit `[u8; 4]` type. | Later enumeration passed in `stage-02/multi-nic-enumeration-2026-07-29.log`; `a900a6d11a0cd5e4d8c0554a7ea8abcdf5b2adc3` (`Verify Stage 2A multi-NIC enumeration`). |
| S2A-002 | Stage 2A | A run emitted the expected marker but its full-regression capture at info verbosity was incomplete, so it could not be used as acceptance evidence. This is an evidence-capture defect, not a claimed kernel failure. | Diagnostic log `stage-02/multi-nic-attempt-02-verbose-log.log`; later rerun uses the dedicated boot acceptance target. | Superseded by the complete enumeration log and Stage 2A verification commit above. |
| S2B-001 | Stage 2B | Initial pipeline build lacked `VecDeque`, the `E: Ext` bound, and valid IPv4 output serialization. | `stage-02/forwarding-pipeline-attempt-01-compile-failure.log`; repair `stage-02/netfilter-stage-02b-forwarding-fix-01.patch`. | Fixed; boot and full regression passed in later Stage 2B logs; `9d07ed117184b0a83dc938138d9a73385805332e`. |
| S2B-002 | Stage 2B | Second pipeline build lacked the kernel `println` import and used the obsolete `Ipv4Addr.0` field. | `stage-02/forwarding-pipeline-attempt-02-compile-failure.log`; repair `stage-02/netfilter-stage-02b-forwarding-fix-02.patch`. | Fixed; boot and full regression passed; `9d07ed117184b0a83dc938138d9a73385805332e`. |
| S2C-001 | Stage 2C | First real TAP forwarding ping panicked with `range end index 84 out of range for slice of length 20`. Forwarding transmit buffers omitted the separate transport-payload length. | Detailed entry in `stage-02/BUGS.md`; raw log `stage-02/router-tap-attempt-01-panic.log`; repair `stage-02/netfilter-stage-02c-forwarding-buffer-fix-01.patch`. | Passed in later 4/4, zero-loss TAP rerun; included in the Stage 2/3 commit. |
| S2C-002 | Stage 2C | Buffer-fix rerun had bidirectional reachability but lost the initial two left-to-right ICMP packets. | ARP request consumed the output token after the routed packet had already been dequeued, dropping it until host ping retransmitted. Repair `stage-02/netfilter-stage-02c-arp-pending-queue-fix-02.patch` preserves the packet for the ARP reply receive poll. | Passed in later 4/4, zero-loss TAP rerun; included in the Stage 2/3 commit. |

## Recording policy

For every future defect, append an entry before the next commit. Preserve the
raw log, give the repair a patch checksum, record the test result, and add the
final local commit SHA after acceptance. Do not remove failed attempts merely
because a later retry passes.
