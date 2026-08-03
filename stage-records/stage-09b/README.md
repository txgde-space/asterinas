# Stage 09B — P0 IPv4 raw sockets and route-aware egress

This stage is intentionally limited to P0 compatibility work:

- `AF_INET/SOCK_RAW` accepts fixed IPv4 protocol numbers `1..=254` instead of
  being hard-coded to ICMP.
- Raw ingress fan-out happens immediately after IPv4 `LOCAL_IN`, before TCP,
  UDP, or ICMP parsing. TCP/UDP and unknown protocol datagrams therefore reach
  the matching raw socket even when the transport parser does not understand
  the payload.
- Raw non-ICMP output uses an opaque IPv4 payload and preserves the selected
  protocol number.
- Unbound IPv4 sends use longest-prefix connected-route selection, then the
  configured gateway interface as the default route. Forwarding reuses the
  same lookup and still excludes its ingress interface.

`IPPROTO_RAW` wildcard-header semantics, IP options (`TTL`, `TOS`), error
queues, and IPv6 raw sockets remain P1 work for the next stage.

The patch depends on Stage 09A (`RTM_GETROUTE`) because the route lookup uses
the gateway metadata introduced there. Apply Stage 09A first, then this patch.

## Acceptance evidence

The initramfs network regression adds:

- `create_multi_protocol_raw_sockets`: ICMP, TCP, UDP, and an experimental
  protocol number can create raw sockets.
- `send_loopback_raw_udp_payload`: a UDP raw payload is emitted as an IPv4
  datagram and received with the complete IPv4 header.

Run the normal regression suite and retain the complete serial output under
`stage-records/stage-09b/` before committing.
