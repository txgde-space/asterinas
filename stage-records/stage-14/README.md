# Stage 14 — dual-stack raw-socket probes and reversible external uplink

This stage does not weaken the default router policy. It makes the interactive
`demo-step` boot opts in to forwarding, exposes an IPv4-only guest-side
local/external probe suite, and provides a reversible Ubuntu namespace uplink.

## Scope

- The Stage14 guest receives only numeric IPv4 probes and executes
  `/bin/ping -4`; DNS is not required inside the guest.
- The dashboard also accepts a hostname such as `baidu.com`: Ubuntu resolves
  its IPv4 A record, records the requested/resolved pair, and sends only the
  numeric address to the guest. The guest itself still has no DNS dependency.
- `probe-suite local` exercises the isolated IPv4 endpoint `10.0.3.2`.
- `probe-suite external` exercises `1.1.1.1` after `setup-uplink`.
- `tools/net/netfilter-external-uplink.sh` owns only its veth, routes, sysctl
  values, and `AST_UPLINK*` chains. `teardown` restores/removes those items.
- IPv6 netfilter rules and the independent Stage10-12 IPv6 acceptance tests are
  retained, but the Stage14 dashboard/uplink workflow does not issue IPv6 ping
  probes. This avoids treating a VMware host without an IPv6 default route as
  an Asterinas failure.

## Acceptance markers

- `NETFILTER_DEMO probe-suite=local rc=0`
- `NETFILTER_DEMO probe-suite=external rc=0` (when the host IPv4 uplink and
  the reversible NAT path are available)
- dashboard shows IPv4 local/external suite buttons and individual probe
  results; IPv6 rule snapshots remain visible for manual inspection.
- `stage-records/demo/netfilter-dashboard-resolution.log` records hostname to
  IPv4 resolution pairs for later evidence and documentation.
