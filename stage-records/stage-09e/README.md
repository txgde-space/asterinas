# Stage 09E — IPv4 `IP_RECVERR` / `MSG_ERRQUEUE`

This stage adds the first observable IPv4 error-queue path for raw sockets:

- `IP_RECVERR` remains a real per-socket option;
- `recvmsg(..., MSG_ERRQUEUE)` dequeues a fixed Linux-compatible
  `sock_extended_err` control message;
- `poll`/`select` expose pending local errors through `POLLERR`;
- local `ENETUNREACH` and raw transmit-queue `ENOBUFS` failures are retained
  when `IP_RECVERR` is enabled;
- an unspecified IPv4 destination is reported as a deterministic local
  `ENETUNREACH` case for compatibility testing;
- the queue is bounded and oldest entries are discarded on overflow;
- empty error queues return `EAGAIN` for nonblocking sockets.

The fixed error record is intentionally limited to the 16-byte
`sock_extended_err` ABI.  ICMP-originated errors, quoted packet payloads and
offending `sockaddr_in` data require a shared ICMP error delivery path and are
reserved for a later stage.

The regression suite checks the nonblocking empty-queue ABI.  Real local
transmit errors are additionally recorded whenever the raw transmit queue or
route selection fails.
