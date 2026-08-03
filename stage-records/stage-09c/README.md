# Stage 09C — IPv4 raw-socket options (P1)

This stage extends the Stage 09B raw IPv4 implementation without changing the
existing routing or netfilter policy surface.

## Scope

- `IPPROTO_RAW` (protocol 255) is accepted for IPv4 raw socket creation. It is
  send-only and requires `IP_HDRINCL` so the supplied IPv4 header selects the
  protocol number.
- Socket-level `IP_TTL` and `IP_TOS` values are carried into generated IPv4
  headers.
- `IP_HDRINCL` preserves source/destination, protocol, TOS, TTL, and total
  length while the stack validates the header and owns the transmit checksum.
- Raw protocol payloads keep using the route-aware egress path from Stage 09B;
  Ethernet and point-to-point interfaces emit the complete IPv4 datagram.

## Acceptance

The raw-socket regression adds an `IPPROTO_RAW` + `IP_HDRINCL` loopback UDP
datagram check. It verifies protocol selection, TOS, TTL, addresses, and the
opaque payload on a matching UDP raw receiver. Run the full regression suite
and retain the resulting log and archive in `stage-records/stage-09c/`.

## Deferred

IPv6 raw sockets, ancillary `IP_TTL`/`IP_TOS` control messages, IP error queues,
fragmentation, and advanced raw-socket filters remain separate follow-up work.
