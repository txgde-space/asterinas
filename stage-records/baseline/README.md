# VMware/KVM Regression Baseline — 2026-07-29

## Result

**Passed.** The complete Asterinas regression suite completed in a VMware
Ubuntu guest using the documented privileged Podman build environment and the
KVM execution path.  The raw console output is preserved in
`regression-kvm-2026-07-29.log`.

SHA-256 of the preserved log (line endings normalized to LF; terminal control
sequences are retained):
`6d1f468e5038ede434ac45f2b3a978a92ce52b4cd43d1edecb559aa2d2d737ee`.

## Report- and presentation-ready summary

| Item | Result |
|---|---|
| Build and boot | Initramfs, ISO construction, and QEMU boot completed |
| Network regression | `All test in /test/network passed.` |
| IPC regression | `All test in /test/ipc passed.` |
| Cgroup CPU accounting | Busy cgroup task increased `usage_usec` and `user_usec` by 1,199,000 microseconds |
| Filesystem regression | `All test in /test/fs passed.` |
| Overall result | `All regression tests passed.` |

The cgroup measurement verifies that the busy task is charged to its cgroup.
It deliberately checks for positive consumed CPU time, not a fixed fraction of
wall-clock time: a VMware guest may be descheduled by its host, so CPU time
cannot be used as a stable wall-clock performance assertion.

The associated test-harness change is in
`test/initramfs/src/regression/process/cgroup.sh`: the busy loop still runs for
two seconds, and both `usage_usec` and `user_usec` must increase.  A zero
delta remains a functional failure.

## Validation context

- Host topology: VMware virtual machine running Ubuntu; nested hardware
  virtualization was available for the KVM path.
- Build environment: privileged `docker.io/asterinas/asterinas:0.18.0-20260603`
  Podman container.
- Intended run configuration: `AUTO_TEST=regression`, serial console `ttyS0`,
  `LOG_LEVEL=error`, `ENABLE_KVM=1`, `SMP=4`, and `RELEASE=1`.  The attached
  log does not preserve the shell invocation, so this configuration is not
  treated as independently captured evidence.
- The QEMU log contains unsupported host CPU-feature warnings and UEFI video
  warnings.  They were non-fatal: all regression pass markers were emitted.

## Evidence caveat

The captured console log begins after the shell command was entered and does
not contain the exact source commit, host package versions, or `git status`.
Those fields are therefore intentionally not reconstructed here.  Subsequent
validation records must use the wrapper in `stage-records/README.md` before
the test command.

## Follow-up

This baseline only establishes that the repository and the virtualization test
environment are healthy.  It does not validate the Stage 1 netfilter change.
The next work item is to compile and execute the Stage 1 focused compatibility
and full-regression acceptance tests, then record their evidence separately.
