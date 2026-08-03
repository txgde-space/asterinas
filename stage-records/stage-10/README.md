# Stage 10A — IPv6 raw socket ABI and loopback dataplane

This stage is the first IPv6 implementation slice after the P0/P1 IPv4 raw
socket work. It deliberately keeps the existing IPv4 Ethernet/router path
unchanged while providing a useful, repeatable IPv6 surface for `ping -6`
and raw-protocol diagnostics.

## Implemented

- parses and writes Linux `sockaddr_in6` values, including flowinfo and scope id;
- accepts `AF_INET6/SOCK_RAW` for protocol numbers 1..255 and preserves
  `IPPROTO_RAW` as a send-only header-including socket;
- supports `bind`, `connect`, `getsockname`, and `getpeername` for `::1`;
- emits and receives complete 40-byte IPv6 packets on the kernel loopback path;
- answers ICMPv6 Echo Requests with a checksum-correct Echo Reply;
- loops arbitrary raw next-header protocols for deterministic probes;
- supports `IPV6_UNICAST_HOPS`, `IPV6_TCLASS`, `IPV6_HDRINCL`, `IPV6_V6ONLY`,
  `IPV6_RECVHOPLIMIT`, and `IPV6_RECVTCLASS` for raw sockets;
- parses per-send `IPV6_HOPLIMIT` and `IPV6_TCLASS` ancillary data;
- exposes bounded local `IPV6_RECVERR` records through `MSG_ERRQUEUE` and
  `POLLERR` when an IPv6 route is not yet available.

## Acceptance coverage

`test/initramfs/src/regression/network/ipv6_any.c` now covers:

1. IPv4-compatible boundary behavior remains explicit: IPv6 TCP/UDP are still
   reported as `EAFNOSUPPORT` in this raw-only stage.
2. ICMPv6 raw loopback echo, `sockaddr_in6`, bind/connect, hop-limit and
   traffic-class gets/sets, per-send hop-limit/traffic-class ancillary data,
   receive ancillary data, and packet header fields.
3. `IPV6_HDRINCL` with an experimental protocol (143), including byte-for-byte
   payload preservation.
4. `IPV6_RECVERR`, `MSG_ERRQUEUE`, and `POLLERR` for a deterministic local
   `ENETUNREACH` result.

## Known boundary

IPv6 Ethernet ingress/egress, neighbor discovery, route/netlink IPv6 dumps,
forwarding, TCP/UDP sockets, extension-header parsing, and external IPv6
connectivity are intentionally reserved for Stage 10B and later. The stage
must not be described as full IPv6 networking; it is the ABI and loopback
foundation required before those paths are added.

## Ubuntu commands

```bash
cd "$HOME/桌面/asterinas" || exit 1
mkdir -p stage-records/stage-10

patch=/mnt/hgfs/asterinas-share/netfilter-stage-10a-ipv6-raw-loopback.patch
test -s "$patch"
sha256sum "$patch" | tee stage-records/stage-10/patch.sha256
git apply --check "$patch" && git apply "$patch"
git diff --check

AUTO_TEST=regression CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 RELEASE=1 \
  make run_kernel 2>&1 | tee stage-records/stage-10/ipv6-raw-regression.log
```

The log is accepted only when it contains both `ipv6_raw_loopback_echo_and_options`
and `All regression tests passed.`. Save the complete log and the SHA-256 digest
to the shared Windows folder before committing.
