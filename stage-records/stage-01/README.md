# Stage 1: IPv4 Filter Foundation

Status: **passed** in the VMware Ubuntu/KVM validation environment on
2026-07-29. Stage 2 may begin; its acceptance evidence must remain separate.

The cross-stage [bug and fix index](../BUGS.md) includes Stage 1 entry S1-001;
the detailed failure and repair evidence remains in this directory.

## Acceptance outcome

| Check | Result |
|---|---|
| Kernel build and QEMU boot | Passed during the full regression run |
| IPv4 network regression | `All test in /test/network passed.` |
| Stage 1 INPUT/FORWARD chain management | 13 assertions passed, 0 failed |
| Address-match regression | 17 assertions passed, 0 failed |
| Whole regression suite | `All regression tests passed.` |

The successful raw console log is `regression-fix-01.log`. It preserves the
complete build, boot, network, IPC, process, and filesystem regression output.
Terminal line endings were normalized to LF for repository consistency while
terminal control sequences were retained.

### First attempt and correction

`regression-attempt-01-buffer-truncation.log` records the only failed Stage 1
attempt. The kernel implementation and new chain-management test passed; one
legacy address-match assertion used a 512-byte procfs snapshot buffer. Stage 1
adds the built-in INPUT and FORWARD chain listings, which placed the existing
`stage20-output-rule-count` line after that buffer. The incremental patch
`netfilter-stage-01-fix-01.patch` increases only that test buffer to 2048
bytes. The second complete regression run passed.

## Transfer package

The uncommitted Stage 1 implementation is packaged as
`netfilter-stage-01.patch` in this directory.  SHA-256:

```text
52958939cfd6e3554eb20162a5de42849c679becef1cacf2b446e32fdb0fd1f2
```

The patch changes seven implementation and regression-test files. It passed
`git apply --check --reverse` against the prepared worktree and
`git diff --check`. The incremental test correction is stored in
`netfilter-stage-01-fix-01.patch` (SHA-256
`f6718562ace0a85774c4cf4c4e168c9c1a9fed3dd3dd37b1ce38efe5a17bc301`).

## Scope of this iteration

- Filter rules are stored independently for the built-in IPv4 `INPUT`,
  `OUTPUT`, and `FORWARD` chains.
- The rule capacity is 64 entries per chain; an exhausted chain returns a
  clear failure instead of overwriting an existing rule.
- TCP and UDP port rules use first-match behavior at the protocol-specific
  hook path for local input, local output, and forwarding.
- ICMP Echo identifier rules are evaluated at the same hook paths.
- Rule mutations require root or `CAP_NET_ADMIN`.
- The previous test-only default ICMP DROP rule is removed. Tests now install
  and remove their own rule explicitly.
- The procfs/iptables-compatible listing exposes each filter chain and its
  stage-1 rule count.

## VMware Ubuntu verification

From the repository root inside the documented Asterinas build container:

```bash
scripts/test-network-compat.sh compile 2>&1 \
  | tee stage-records/stage-01/network-compat-compile.log
make kernel 2>&1 \
  | tee stage-records/stage-01/build.log
AUTO_TEST=regression make run_kernel 2>&1 \
  | tee stage-records/stage-01/regression.log
```

The focused test list must compile, and the QEMU log must contain:

```text
All test in /test/network passed.
All regression tests passed.
```

The regression log must also include the stage-1 chain-management test:

```text
run_userspace_iptables_input_forward_filter_chains
```

## Evidence manifest

| File | SHA-256 |
|---|---|
| `netfilter-stage-01.patch` | `52958939cfd6e3554eb20162a5de42849c679becef1cacf2b446e32fdb0fd1f2` |
| `netfilter-stage-01-fix-01.patch` | `f6718562ace0a85774c4cf4c4e168c9c1a9fed3dd3dd37b1ce38efe5a17bc301` |
| `regression-attempt-01-buffer-truncation.log` | `71db8afdcf3b847fd5309bf554f0502752d169ea369def9728a83cb3bd114a13` |
| `regression-fix-01.log` | `941e2af8e354901d3a460b6b4996eb3faf2d321c60bc7bf20dec95b08eb4eb9e` |

The separate `scripts/test-network-compat.sh compile` output was not included
in the transferred evidence. Its coverage is nevertheless subsumed in the
successful full build and runtime regression; future records must retain its
raw log explicitly.

Before committing later stages, record checksums with:

```bash
git rev-parse HEAD
find stage-records/stage-01 -maxdepth 1 -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > stage-records/stage-01/sha256sums.txt
```

This acceptance record is complete. The Stage 1 implementation, its focused
test correction, and this evidence are committed together; no push is made.
