# Stage8-Demo: Asterinas Netfilter Lab

This auxiliary stage adds a presentation-oriented Web dashboard without
changing kernel behavior. The guest walkthrough emits `NETFILTER_DEMO` records
and `/proc/netfilter_rules` snapshots. A dependency-free Python HTTP server
follows the serial transcript and also controls the walkthrough:

- the isolated two-interface IPv4 topology;
- filter, conntrack, and NAT scenario progress;
- the latest rules and packet/byte counters;
- representative original and translated packet tuples;
- the iptables action timeline and return codes.
- a current-step indicator with `下一步`, `重置`, and scenario execution;
- a QEMU serial control socket, so buttons execute commands in the guest rather
  than merely replaying a pre-recorded trace.

## Run

On the Ubuntu host, from the repository root:

```bash
chmod +x tools/net/netfilter-demo.sh
./tools/net/netfilter-demo.sh prepare
./tools/net/netfilter-demo.sh serve
```

Open `http://127.0.0.1:8080/` in the Ubuntu browser. In a second terminal,
start the normal privileged Asterinas container and run:

```bash
cd /root/asterinas
mkdir -p stage-records/demo
AUTO_TEST=demo CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 RELEASE=1 \
  make run_kernel 2>&1 | tee stage-records/demo/netfilter-demo.log
```

`AUTO_TEST=demo-step` builds the regression initramfs and starts the interactive
`netfilter_demo_step` binary. The QEMU serial stream is written to
`stage-records/demo/netfilter-demo-step-serial.log` and the control socket is
`stage-records/demo/netfilter-demo-step.sock`. Use the Web buttons to advance
one real operation at a time, reset the rules, or run `filter`, `conntrack`,
`nat`, or `all` automatically. For a terminal-only walkthrough, install
`socat` and run `./tools/net/netfilter-demo.sh connect`.

The older `AUTO_TEST=demo` mode remains available for a non-interactive trace.
The dashboard updates while either mode emits `NETFILTER_DEMO` records. The
`filter` scenario shows DROP, `-C`, and `-R`; `conntrack` shows NEW and
ESTABLISHED policy rules; `nat` shows DNAT and MASQUERADE rule paths. The host
Stage 2C/Stage 3/Stage 4 topology harness remains the authoritative evidence
for actual cross-interface packet delivery and translated wire tuples.

## Scope and limitations

The control endpoint is bound to loopback by default and only writes the small
demo command vocabulary to the QEMU serial socket; it does not alter the host
firewall. The current snapshot format is the project's
`/proc/netfilter_rules` compatibility format, not the Linux xtables or nftables
ABI. The Stage 2C/Stage 3/Stage 4 topology harness remains the authoritative
evidence for cross-interface delivery and translated wire tuples.
