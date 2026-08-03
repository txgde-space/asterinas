# Stage 10B — IPv6 interface identity and rtnetlink route/address dumps

Stage 10B extends the Stage 10A IPv6 raw-socket loopback foundation with a
real interface model. It does not claim external IPv6 packet delivery yet;
the Ethernet receive/transmit and neighbor-discovery path remains the next
slice.

## Implemented

- enables the vendored smoltcp IPv6 wire model;
- assigns deterministic ULA addresses to `lo` and virtio interfaces:
  `::1/128`, `fd00:0:0:2::15/64`, `fd00:0:0:3::15/64`, ...;
- installs per-interface IPv6 connected routes and a static default next hop;
- exposes IPv6 address/prefix/gateway information through the common iface API;
- implements IPv6 `RTM_GETADDR` and `RTM_GETROUTE` dump responses, including
  16-byte `IFA_ADDRESS`, `IFA_LOCAL`, `RTA_DST`, `RTA_GATEWAY`, and
  `RTA_PREFSRC` payloads;
- keeps `AF_UNSPEC` dumps dual-stack while preserving the IPv4-only behavior
  and output of the earlier stages.

## Acceptance

The network regression must contain all of the following markers:

```text
test_ipv6_route_dump summary: IPv6 RTM_GETROUTE dump passed
test_ipv6_addr_dump summary: IPv6 RTM_GETADDR dump passed
get_ipv6_route_dump summary: ...
All regression tests passed.
```

Run the same container/QEMU command used for the previous stages and capture
the complete output:

```bash
mkdir -p stage-records/stage-10b
AUTO_TEST=regression CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 RELEASE=1 \
  make run_kernel 2>&1 | tee stage-records/stage-10b/ipv6-netlink-regression.log
```

Known limitation: IPv6 Ethernet ingress/egress, neighbor discovery, IPv6
forwarding, and IPv6 TCP/UDP are not enabled by this stage. Their route and
address metadata is now present so the next packet-path stage can use the
same interface configuration.
