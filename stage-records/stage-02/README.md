# Stage 2: Multi-NIC and IPv4 Forwarding

Status: **in progress.** Stage 2A multi-NIC enumeration passed on 2026-07-29.
Stage 2B's forwarding pipeline compiled, booted, and passed the complete
existing regression suite with multi-NIC and forwarding enabled on 2026-07-30.
This preserves existing kernel behavior but does not yet prove
endpoint-to-endpoint forwarding, TTL/ICMP behavior, or NAT.

## Implemented scope

- Each virtio network device receives a unique `Virtio-Net-N` registry name,
  preventing a second device from overwriting the first device-table entry.
- Interface initialization enumerates registered virtio NICs and creates
  `eth0`, `eth1`, and later numbered interfaces with deterministic user-net
  addresses `10.0.(2 + N).15/24`.
- `MULTI_NET=on` adds a second QEMU user-net backend on `10.0.3.0/24` for
  enumeration development. It is intentionally not represented as a router
  end-to-end topology.

### Stage 2B: forwarding-pipeline implementation

- Add an opt-in `netfilter.ipv4_forward=on` kernel command-line switch. The
  default is disabled.
- Distinguish non-local IPv4 ingress from local delivery after `PREROUTING`.
- Evaluate generic and protocol-specific `FORWARD` filter hooks before route
  selection, and evaluate `POSTROUTING` before physical transmission.
- Select a directly connected egress interface by longest-prefix match,
  excluding the ingress interface; decrement the IPv4 hop limit before
  enqueueing output.
- Add bounded (256-packet) forwarding queues to the bigtcp common interface
  path and emit queued forwarded IPv4 packets through Ethernet or IP media,
  recomputing the IPv4 header checksum during serialization.

This is deliberately a minimal forwarding foundation. The current router does
not yet expose a route table, generate distinct ICMP errors for route/TTL/queue
failure, handle fragmentation or MTU, or provide NAT/conntrack.

## Verification results

| Acceptance item | Result | Evidence |
|---|---|---|
| Default single-NIC regression | Passed | `regression-default-2026-07-29.log` ends with `All regression tests passed.` |
| Two-NIC kernel boot and enumeration | Passed | `multi-nic-enumeration-2026-07-29.log` line 445 reports `netfilter-stage2a: multi-nic enumeration passed`; line 475 reports `Successfully booted.` |
| Stage 2B forwarding pipeline build and boot | Passed | `forwarding-pipeline-boot-2026-07-30.log`: release build completed in 1m 08s, kernel emitted `netfilter-stage2b: ipv4 forwarding pipeline enabled`, then `Successfully booted.` |
| Stage 2B complete existing regression | Passed | `forwarding-pipeline-regression-2026-07-30.log`: Stage 2B marker at line 285; network suite passed at line 5445; complete regression passed at line 21123. |
| Full Stage 2 IPv4 forwarding | Not yet accepted | Requires a full regression run and then an isolated endpoint topology proving bidirectional forwarding, `FORWARD`, TTL, and ICMP-error behavior. |

The accepted command was:

```bash
make stage2_multi_nic_check
```

It runs the boot test with `MULTI_NET=on`, KVM, serial console, and the kernel
command-line test flag. The target fails unless the kernel confirms `eth0`
has `10.0.2.15/24` and `eth1` has `10.0.3.15/24`.

### Stage 2B boot acceptance

The successful raw log is preserved as
`forwarding-pipeline-boot-2026-07-30.log`. Its command/environment and VM
worktree commit were not captured in the submitted log, so they are recorded
as unavailable rather than inferred. The log establishes only the following:

- two optimized release builds completed, with the latter taking 1m 08s;
- the kernel reached the Stage 2B marker with IPv4 forwarding enabled; and
- QEMU reported `Successfully booted.`

The log also includes `error: no suitable video mode found.` and firmware/CPU
messages. These occur before the kernel marker and do not prevent the serial
boot acceptance. They are not treated as a Stage 2B functional failure.

### Stage 2B regression acceptance

The complete raw regression log is preserved as
`forwarding-pipeline-regression-2026-07-30.log`. It was run with KVM, four
virtual CPUs, release mode, two QEMU network backends, and
`netfilter.ipv4_forward=on`:

```bash
cd /root/asterinas
AUTO_TEST=regression CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 \
RELEASE=1 MULTI_NET=on \
EXTRA_KCMD_ARGS='--kcmd-args="netfilter.ipv4_forward=on"' \
make run_kernel 2>&1 | tee stage-records/stage-02/forwarding-pipeline-regression.log
```

The build completed in 0.18s using existing artifacts. The kernel emitted the
Stage 2B enablement marker, `/test/network` passed, and the run ended with
`All regression tests passed.` This accepts Stage 2B's compatibility regression
only. It does not replace the later TAP-backed functional forwarding tests.

Two compile attempts are retained as diagnostic evidence. Attempt 01 exposed
a missing `VecDeque` import, a missing `E: Ext` bound, and invalid direct
`Ipv4Repr` serialization. Fix 01 added the import/bound and serializes through
an `Ipv4Packet` wrapper. Attempt 02 exposed a missing `println` macro import
and use of the obsolete `Ipv4Addr.0` representation. Fix 02 imports the macro
and uses `Ipv4Address::octets()`.

### Default-path regression

The supplied VMware raw log was preserved without modification as
`regression-default-2026-07-29.log`. It shows that the patched tree compiled
`aster-virtio` and `aster-kernel`, booted QEMU, passed the existing netfilter
network checks, and ended with:

```text
All regression tests passed.
```

This establishes that the default single-NIC runtime path remains compatible.

The uploaded log does not contain the VMware worktree's Git HEAD or its exact
launch environment. The local source patch was prepared on top of
`70876a8f6344450cedcf1d674afd1a655b7bab50`; no unrecorded VM commit is
inferred.

### Earlier verification attempts

- The first automated-check build failed with Rust error `E0282` because the
  IPv4-address closure parameter had no inferred type. The follow-up patch
  records the explicit `[u8; 4]` type.
- The second run emitted the success marker but used the full regression suite
  at info verbosity; its captured log is incomplete, so it is retained as
  diagnostic evidence and is not used as an acceptance result.

## Evidence manifest

| File | SHA-256 |
|---|---|
| `netfilter-stage-02a.patch` | `119afce0d73b295fda9d4db1479a1b220bb53356fabe91b0877abc268acc563d` |
| `regression-default-2026-07-29.log` | `4ce4b769c9d45b9552ab54ea1be269bcf36462bcd6600cf1169771e5585d57ec` |
| `netfilter-stage-02a-check.patch` | `aaededf1ce85d2df5c2feb96d38cb80739e7f71ef7df62669117e4aa0f0deeac` |
| `netfilter-stage-02a-check-fix-01.patch` | `eeeb1b1818fd4a2cee88fdc6d8d964d0f9bee141cdc00746d321bd20b5810e35` |
| `netfilter-stage-02a-check-fix-02.patch` | `82fbc4acc8b21c11f5b586621ef1af35a64b911ebc22f1d0e37ca2d36fefe192` |
| `netfilter-stage-02a-check-fix-03.patch` | `34a228cf7837c46b586e837fe0d6c32d7aac5d1fd541f0aa96e43068a4edb8e3` |
| `multi-nic-attempt-01-build-failure.log` | `88fd5308fda0f891c189760ff650a426533af375d34e5b27377adc6eec2a3131` |
| `multi-nic-attempt-02-verbose-log.log` | `7d4530ec7543edd5fe4ff89e74f8ca3e20898fa119882b759a5d1f46c26d6a9a` |
| `multi-nic-enumeration-2026-07-29.log` | `b31c25fffed7643bd2743f194dda8201454f5eef1ba1f869d6a42230bb7beb75` |
| `netfilter-stage-02b-forwarding-pipeline.patch` | `508ea0cce58320f5f6f7c712ba0fcdac445a634ee360b28ef63ed368835831c` |
| `netfilter-stage-02b-forwarding-fix-01.patch` | `f10e652c60e2589e774ad7eedfc14dc4a0c246140f32b5dc413bc6eec38e4c37` |
| `netfilter-stage-02b-forwarding-fix-02.patch` | `3ed6d9c26264fb7c22ec14a3bb2ab857965548bfadd918db6054e4a7db47e97a` |
| `forwarding-pipeline-attempt-01-compile-failure.log` | `82ef833881ae2fc825862dc07fc4bcbb3172287fe17d3cd86d540102235c0065` |
| `forwarding-pipeline-attempt-02-compile-failure.log` | `88b5391aa2df96a9fe37fc655e939b468b04b9819af26dc6553f04c6aa163e1b` |
| `forwarding-pipeline-boot-2026-07-30.log` | `1322853f9544e8fd8a9fbb4bde775538139fa2ba2c547ca1390b2d3ef69bee05` |
| `forwarding-pipeline-regression-2026-07-30.log` | `7098ae1a0d27af2853036429864be0153be3cc656ab6f77c5f9c35dbdf0bfe21` |

## Next acceptance command

Before committing Stage 2B, run the complete existing regression suite with
the multi-NIC and forwarding switch enabled:

```bash
cd /root/asterinas
AUTO_TEST=regression \
CONSOLE=ttyS0 \
LOG_LEVEL=error \
ENABLE_KVM=1 \
SMP=4 \
RELEASE=1 \
MULTI_NET=on \
EXTRA_KCMD_ARGS='--kcmd-args="netfilter.ipv4_forward=on"' \
make run_kernel 2>&1 | tee stage-records/stage-02/forwarding-pipeline-regression.log
```

The complete regression passed on 2026-07-30, so the Stage 2B implementation
and its evidence are ready for one local commit. The subsequent router
acceptance will replace user-net with isolated TAP-backed endpoint networks and
prove bidirectional forwarding, `FORWARD` filtering, TTL expiry, route-miss
behavior, and `POSTROUTING` behavior.
