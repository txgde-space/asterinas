# Stage 10C — Ethernet IPv6 receive path, NDP, and ICMPv6 echo

Stage 10C turns the IPv6 interface metadata from Stage 10B into a usable
same-link packet path.  It accepts Ethernet IPv6 frames (including multicast
destinations), learns neighbors from NDP options, answers Neighbor Solicitation
with a standards-shaped Neighbor Advertisement, and answers ICMPv6 Echo
Requests with a checksum-correct Echo Reply.  The Ethernet resolver also maps
known IPv6 neighbors and IPv6 multicast addresses to Ethernet destinations for
future egress packets.

The acceptance helper extends the existing isolated TAP topology with ULA
addresses on the two endpoint namespaces.  `test-ipv6` deliberately tests a
same-link ping to the guest (`fd00:0:0:2::15`) so it exercises NDP and the
Ethernet receive/transmit path without claiming IPv6 forwarding.

## Scope boundary

Included:

- IPv6 Ethernet frame recognition and multicast admission;
- NDP Neighbor Solicitation/Advertisement handling and a small neighbor cache;
- ICMPv6 Echo Request/Reply, including IPv6 pseudo-header checksum generation;
- repeatable host-side TAP test and IPv6 endpoint addressing.

Deferred to the next packet-path stages:

- IPv6 forwarding between the two TAP links and hop-limit/error generation;
- IPv6 UDP/TCP sockets and IPv6 netfilter/NAT rules;
- neighbor-cache expiry, retransmission queues, and raw IPv6 socket delivery
  for non-loopback traffic.

## Acceptance

After applying the patch, set up the topology and boot the kernel with the
same `NETDEV=router-tap` command used by the earlier stages.  On the Ubuntu
host run:

```bash
sudo ./tools/net/stage2-router-topology.sh test-ipv6 \
  2>&1 | tee stage-records/stage-10c/ipv6-ethernet.log
```

The log must contain:

```text
netfilter-stage10c: IPv6 NDP + Ethernet ICMPv6 echo passed
```

The normal regression command must still end with `All regression tests
passed.`; it covers the Stage 10A raw IPv6 loopback ABI and Stage 10B address
and route dumps.
