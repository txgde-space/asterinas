# Stage 10D — IPv6 forwarding and Hop Limit

Stage 10D extends the Stage 10C Ethernet/NDP path across the two isolated
router links. A non-local unicast IPv6 datagram is copied from ingress,
decremented by one Hop Limit, routed by the platform using connected IPv6
prefixes, and emitted on the selected egress interface. If the egress
neighbor is unknown, the packet remains queued while the router sends an NDP
Neighbor Solicitation; the following Neighbor Advertisement releases it.

## Acceptance

Boot the guest with IPv6 forwarding enabled:

```bash
EXTRA_KCMD_ARGS='--kcmd-args="netfilter.ipv4_forward=on netfilter.ipv6_forward=on"' \
NETDEV=router-tap ROUTER_TAP0=as2tap0 ROUTER_TAP1=as2tap1 \
CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 RELEASE=1 \
make run_kernel
```

On the Ubuntu host:

```bash
sudo ./tools/net/stage2-router-topology.sh test-ipv6-forward \
  2>&1 | tee stage-records/stage-10d/ipv6-forwarding.log
```

The log must contain:

```text
netfilter-stage10d: bidirectional IPv6 forwarding passed
```

The test sends four ICMPv6 Echo Requests in both directions. It also causes
the router to resolve the right-side and left-side endpoint MAC addresses via
NDP, so success covers forwarding, Hop Limit decrement, NDP queue release,
and reverse-path forwarding.

## Scope boundary

Included:

- IPv6 connected-prefix route lookup and per-interface forwarding queues;
- Hop Limit decrement and drop of packets with an expired Hop Limit;
- NDP solicitation generation for unresolved forwarded destinations;
- opaque forwarding of IPv6 extension headers and TCP/UDP payloads.

Deferred:

- IPv6 netfilter rule matching and IPv6 NAT;
- IPv6 raw socket delivery for non-loopback traffic;
- ICMPv6 Time Exceeded and Destination Unreachable generation;
- neighbor-cache expiry and retransmission timers.
