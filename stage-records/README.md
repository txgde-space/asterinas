# Netfilter Development and Verification Record

This directory records the implementation and verification evidence for the
five-stage netfilter, forwarding, conntrack, NAT, and userspace compatibility
roadmap.

## Status

| Stage | Scope | Status |
|---|---|---|
| Baseline | VMware/KVM full regression | Passed (2026-07-29) |
| 1 | IPv4 filter chains and rule-management foundation | Passed (2026-07-29) |
| 2 | Multi-interface IPv4 forwarding | In progress — Stage 2A enumeration and Stage 2B forwarding pipeline/regression passed; full end-to-end forwarding pending |
| 3 | Bounded connection tracking | Planned |
| 4 | Bidirectional SNAT, MASQUERADE, and DNAT | Planned |
| 5 | iptables compatibility and VM/container scenarios | Planned |

Update this table only after the corresponding stage acceptance criteria have
been executed. A successful compilation alone does not count as a passed
runtime test.

## Evidence Layout

Store evidence under `baseline` or a directory named `stage-NN`:

```text
stage-records/
  baseline/
    README.md
    regression-kvm-2026-07-29.log
  stage-01/
    README.md
    commands.log
    build.log
    regression.log
    environment.txt
    sha256sums.txt
```

Each stage record must contain:

1. The exact Git commit and whether the worktree was clean.
2. Host, VM, container, compiler, QEMU, and kernel versions.
3. Commands in execution order.
4. Complete build and runtime logs.
5. A pass/fail table mapped to the stage acceptance criteria.
6. Known limitations and follow-up items.

Large generated images, VM disks, and container layers must not be committed.
Record their source, version, size, and SHA-256 digest instead.

## Evidence Standard for Future Key Updates

For every independently meaningful implementation change or successful
validation, create or update one evidence record before committing it.  The
record must preserve a complete raw log and a concise `README.md` summary that
can be reused by the technical report and presentation.  The summary must
state: objective, implementation/change, exact command (including relevant
environment variables), environment, pass/fail markers, quantitative results,
known limitations, and the associated commit SHA after the commit is made.

If the raw log omitted the command, commit, or environment, explicitly mark
that field as unavailable; do not infer it.  The next run must capture it with
the wrapper below:

```bash
mkdir -p stage-records/<scope>
{
  date --iso-8601=seconds
  git rev-parse HEAD
  git status --short
  uname -a
  podman --version
  qemu-system-x86_64 --version
  printf 'COMMAND: %q ' AUTO_TEST=regression CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 RELEASE=1 make run_kernel
  printf '\n'
} > stage-records/<scope>/environment.txt

AUTO_TEST=regression CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 RELEASE=1 \
  make run_kernel 2>&1 | tee stage-records/<scope>/regression.log
```

After a successful acceptance run, check formatting, generate SHA-256 digests,
and commit only the implementation and its matching evidence.  Never push
automatically.

## VMware Ubuntu Validation Host

Use an x86-64 Ubuntu 24.04 LTS VMware guest with at least:

- 8 virtual CPUs;
- 16 GiB RAM;
- 80 GiB free disk space;
- hardware virtualization exposed to the guest.

In VMware settings, enable the option that exposes Intel VT-x/EPT or AMD-V/RVI
to the virtual machine. After booting Ubuntu, verify nested virtualization:

```bash
grep -Eoc '(vmx|svm)' /proc/cpuinfo
test -e /dev/kvm
ls -l /dev/kvm
```

The first command must print a non-zero value and `/dev/kvm` must exist. If
these checks fail, power off the VM and enable nested virtualization before
continuing. QEMU software emulation is substantially slower and is not the
reference validation environment.

Install the host prerequisites:

```bash
sudo apt update
sudo apt install -y \
  git make gcc curl jq \
  podman qemu-system-x86 qemu-utils ovmf \
  cpu-checker
kvm-ok
```

Clone the repository and capture the initial environment:

```bash
git clone https://github.com/JuneSunyew/asterinas.git
cd asterinas
mkdir -p stage-records/baseline
{
  date --iso-8601=seconds
  uname -a
  lsb_release -a
  git status --short --branch
  git rev-parse HEAD
  podman --version
  qemu-system-x86_64 --version
} 2>&1 | tee stage-records/baseline/environment.txt
```

Run the repository's documented privileged build container:

```bash
sudo podman run --rm -it --privileged \
  --network=host \
  -v /dev:/dev \
  -v "$PWD:/root/asterinas" \
  docker.io/asterinas/asterinas:0.18.0-20260603
```

Inside the container:

```bash
cd /root/asterinas
make kernel 2>&1 | tee stage-records/baseline/build.log
AUTO_TEST=regression make run_kernel 2>&1 \
  | tee stage-records/baseline/regression.log
```

The baseline is accepted only when the log contains both:

```text
All test in /test/network passed.
All regression tests passed.
```

Also compile the focused compatibility tests:

```bash
scripts/test-network-compat.sh compile 2>&1 \
  | tee stage-records/baseline/network-compat-compile.log
```

This command only checks compilation. It does not replace the QEMU regression
run.

For an interactive distribution image:

```bash
make nixos 2>&1 | tee stage-records/baseline/nixos-build.log
make run_nixos
```

Before committing evidence, remove terminal control characters if necessary
and generate checksums:

```bash
find stage-records/baseline -maxdepth 1 -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > stage-records/baseline/sha256sums.txt
```

## Stage 1: IPv4 Filter Foundation

Goal: provide consistent, configurable filtering for locally delivered,
locally generated, and forwarded IPv4 packets.

Implementation:

- remove test-only rules from the default production rule set;
- introduce a common packet context containing hook, protocol, addresses,
  ports, ICMP metadata, packet length, and input/output interfaces;
- provide independent `INPUT`, `OUTPUT`, and `FORWARD` chains;
- support ordered first-match evaluation and configurable default policies;
- support append, insert, replace, delete, flush, zero, list, and policy
  operations;
- support IPv4 CIDR, protocol, TCP/UDP ports, ICMP type/code, and interface
  matching;
- enforce `CAP_NET_ADMIN` on all rule mutations;
- replace small fixed rule arrays with an explicitly bounded dynamic ruleset;
- publish rule-limit, drop, and update-failure counters.

Acceptance:

- an empty ruleset accepts existing network regression traffic;
- an INPUT rule can block and restore access to a guest service;
- an OUTPUT rule can block and restore ICMP, TCP, and UDP traffic;
- a FORWARD rule is parsed and evaluated by a synthetic forwarding test;
- first-match and chain policy behavior match the documented subset;
- concurrent readers never observe a partially updated ruleset;
- `make check`, focused unit tests, kernel tests, and full network regression
  pass.

## Stage 2: Multi-interface IPv4 Forwarding

Goal: make Asterinas act as an IPv4 router between two interfaces.

Implementation:

- add an explicit IPv4 forwarding switch, defaulting to disabled;
- perform route lookup after `PREROUTING`;
- distinguish local delivery from forwarding;
- decrement TTL and update the IPv4 checksum;
- evaluate the `FORWARD` chain before egress;
- resolve the output interface and evaluate `POSTROUTING`;
- generate correct ICMP Time Exceeded, Destination Unreachable, and
  Fragmentation Needed errors;
- define MTU and fragmentation behavior;
- expose forwarding state and counters through a stable control surface.

Acceptance:

- two isolated endpoints communicate through an Asterinas router with
  forwarding enabled;
- forwarding disabled produces the documented failure;
- INPUT, OUTPUT, and FORWARD rules affect only their intended paths;
- TTL expiry generates ICMP Time Exceeded;
- route miss and MTU failure generate the expected ICMP errors;
- bidirectional TCP, UDP, and ICMP forwarding pass in a two-interface QEMU
  topology.

## Stage 3: Bounded Connection Tracking

Goal: track bidirectional IPv4 TCP, UDP, and ICMP Echo flows safely.

Implementation:

- define canonical original and reply tuples;
- use a bounded hash table with explicit memory limits;
- support bidirectional lookup;
- implement UDP, ICMP, and simplified TCP timeouts and state transitions;
- implement periodic garbage collection without blocking packet processing;
- expose `NEW`, `ESTABLISHED`, `RELATED`, and `INVALID` where supported;
- add per-protocol occupancy, eviction, expiry, and allocation-failure
  counters;
- document lock ordering and avoid I/O under packet-path locks.

Acceptance:

- forward and reply packets resolve to one connection entry;
- concurrent flows do not reuse an active translated tuple;
- expired entries are reclaimed;
- table exhaustion is bounded and observable;
- TCP, UDP, and ICMP lifecycle tests pass;
- malformed and out-of-state packets have deterministic behavior.

## Stage 4: Bidirectional NAT

Goal: provide connection-correct SNAT, MASQUERADE, and DNAT.

Implementation:

- apply DNAT in `PREROUTING` before route lookup;
- apply SNAT and MASQUERADE in `POSTROUTING`;
- allocate translated TCP/UDP ports with collision detection;
- store NAT decisions in conntrack and reuse them for every packet;
- reverse translations on reply traffic;
- update IPv4, TCP, UDP, and ICMP checksums;
- translate ICMP Echo identifiers;
- handle related ICMP errors containing an embedded flow tuple;
- define fragment handling and reject unsupported fragments safely;
- handle interface-address changes for MASQUERADE.

Acceptance:

- a private endpoint reaches an external TCP/UDP service through SNAT;
- reply traffic is restored to the original private tuple;
- MASQUERADE uses the selected egress-interface address;
- DNAT port forwarding reaches the intended internal service;
- concurrent connections receive non-conflicting translated ports;
- packet capture on both interfaces proves addresses, ports, and checksums;
- conntrack and NAT entries expire without leaks.

## Stage 5: Userspace and Virtualization Integration

Goal: validate typical iptables workflows and a realistic VM/container network.

Implementation:

- expand the compatibility command set and listing format;
- support atomic save/restore for the documented subset;
- decide and document either an `iptables-legacy` xtables ABI subset or an
  nfnetlink/nftables ABI path;
- support stable rule handles and transactional replacement;
- integrate the networking primitives required by the selected scenario,
  such as multiple virtio-net devices, TAP, bridge, or veth;
- isolate rules and conntrack per network namespace if network namespaces are
  included in the claimed scope;
- add boot-time configuration and capability checks.

Acceptance:

- documented `iptables` filter and NAT commands run without direct procfs
  writes by the user;
- save/restore reproduces an equivalent ruleset atomically;
- an Asterinas router connects a private VM network to an external network;
- DNAT exposes an internal HTTP service;
- filter rules isolate two workloads while allowing explicitly permitted
  traffic;
- reboot, rule reload, concurrent traffic, and table-pressure tests pass;
- the final report clearly distinguishes native Linux ABI support from the
  project compatibility shim.

## Commit Policy

Each stage is committed only when its acceptance tests pass. Use one logical
change per commit, do not mix refactoring with behavior changes, and do not
push automatically. Record the commit SHA and test summary in the corresponding
stage record.
