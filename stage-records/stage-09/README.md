# Stage 9A: read-only `RTM_GETROUTE` compatibility

## Delivered scope

- Decodes `RTM_GETROUTE` requests on `NETLINK_ROUTE`.
- Supports the `NLM_F_DUMP` IPv4 route-table query used by `ip -4 route`.
- Reports directly-connected IPv4 routes for every configured interface.
- Reports the configured Ethernet next hop as a conventional default route.
- Emits `RTM_NEWROUTE` records followed by `NLMSG_DONE`, preserving the
  request sequence and port identifiers.
- Keeps route mutation, IPv6, policy routing, multipath, and dynamic route
  management outside this stage.

## Regression gate

`netlink_route.c` now sends an IPv4 `RTM_GETROUTE|NLM_F_DUMP` request and
requires at least one `RTM_NEWROUTE` response plus `NLMSG_DONE`. On the guest,
the acceptance command is:

```text
ip -4 route
```

The regression also runs `route_dump.sh`; the command must return promptly and
show the connected route and the default next hop (for example, `default via
10.0.2.2 dev eth0`).

## Compatibility boundary

This is a read-only IPv4 dump. Route filters in request attributes are consumed
but not applied. IPv6, `RTM_NEWROUTE`/`RTM_DELROUTE`, table mutation, metrics,
policy rules, multipath, and per-network-namespace route ownership remain
future work.
