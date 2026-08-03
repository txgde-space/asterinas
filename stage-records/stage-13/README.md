# Stage 13 — Netfilter control dashboard

This stage keeps the Asterinas packet path unchanged and adds a local-only
presentation/control surface around the existing `demo-step` serial channel.

It provides:

- live IPv4 and IPv6 filter/NAT snapshots, chain policies, packet/byte counters,
  flow events, and a control timeline;
- a validated subset of `iptables` and `ip6tables` commands (`-A`, `-I`, `-D`,
  `-F`, `-P`, `-Z`, `-L` for the guest parser's `filter` and `nat` tables);
- IPv4 and IPv6 numeric-address ping probes executed inside the guest with
  `/bin/ping -4` or `/bin/ping -6`, including result history.

The dashboard binds to `127.0.0.1` by default. It is not a general-purpose
iptables shell: unsupported matches, tables, command substitution, DNS names,
and unbounded probes are rejected by the host UI before reaching the guest.

After the walkthrough reaches `complete=1`, the guest keeps the serial control
channel open so the presenter can continue changing rules or running probes.
Use the dashboard Reset button for a fresh walkthrough; `quit` is available
only from a raw serial console when the QEMU session should terminate.
