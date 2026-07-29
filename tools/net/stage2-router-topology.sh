#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0

# Creates only the isolated host-side topology used by Stage 2C forwarding
# acceptance. QEMU owns the two TAP file descriptors, while the endpoint
# namespaces provide two independent IPv4 hosts.

set -euo pipefail

LEFT_NS=as2left
RIGHT_NS=as2right
LEFT_BR=as2br0
RIGHT_BR=as2br1
LEFT_TAP=as2tap0
RIGHT_TAP=as2tap1
LEFT_HOST_VETH=as2h0
RIGHT_HOST_VETH=as2h1
LEFT_NS_VETH=as2e0
RIGHT_NS_VETH=as2e1

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run this script on the Ubuntu host with sudo." >&2
        exit 1
    fi
}

any_resource_exists() {
    ip link show "$LEFT_BR" >/dev/null 2>&1 ||
        ip link show "$RIGHT_BR" >/dev/null 2>&1 ||
        ip link show "$LEFT_TAP" >/dev/null 2>&1 ||
        ip link show "$RIGHT_TAP" >/dev/null 2>&1 ||
        ip netns list | awk '{print $1}' | grep -qx "$LEFT_NS" ||
        ip netns list | awk '{print $1}' | grep -qx "$RIGHT_NS"
}

topology_is_ready() {
    ip link show "$LEFT_BR" >/dev/null 2>&1 &&
        ip link show "$RIGHT_BR" >/dev/null 2>&1 &&
        ip link show "$LEFT_TAP" >/dev/null 2>&1 &&
        ip link show "$RIGHT_TAP" >/dev/null 2>&1 &&
        ip netns list | awk '{print $1}' | grep -qx "$LEFT_NS" &&
        ip netns list | awk '{print $1}' | grep -qx "$RIGHT_NS"
}

setup() {
    if any_resource_exists; then
        echo "Stage 2C topology resources already exist; run '$0 teardown' first." >&2
        exit 1
    fi

    ip link add name "$LEFT_BR" type bridge
    ip link add name "$RIGHT_BR" type bridge
    ip link set "$LEFT_BR" up
    ip link set "$RIGHT_BR" up

    ip tuntap add dev "$LEFT_TAP" mode tap user root
    ip tuntap add dev "$RIGHT_TAP" mode tap user root
    ip link set "$LEFT_TAP" master "$LEFT_BR"
    ip link set "$RIGHT_TAP" master "$RIGHT_BR"
    ip link set "$LEFT_TAP" up
    ip link set "$RIGHT_TAP" up

    ip netns add "$LEFT_NS"
    ip link add "$LEFT_HOST_VETH" type veth peer name "$LEFT_NS_VETH"
    ip link set "$LEFT_NS_VETH" netns "$LEFT_NS"
    ip link set "$LEFT_HOST_VETH" master "$LEFT_BR"
    ip link set "$LEFT_HOST_VETH" up
    ip -n "$LEFT_NS" link set lo up
    ip -n "$LEFT_NS" link set "$LEFT_NS_VETH" name eth0
    ip -n "$LEFT_NS" addr add 10.0.2.2/24 dev eth0
    ip -n "$LEFT_NS" link set eth0 up
    ip -n "$LEFT_NS" route add default via 10.0.2.15

    ip netns add "$RIGHT_NS"
    ip link add "$RIGHT_HOST_VETH" type veth peer name "$RIGHT_NS_VETH"
    ip link set "$RIGHT_NS_VETH" netns "$RIGHT_NS"
    ip link set "$RIGHT_HOST_VETH" master "$RIGHT_BR"
    ip link set "$RIGHT_HOST_VETH" up
    ip -n "$RIGHT_NS" link set lo up
    ip -n "$RIGHT_NS" link set "$RIGHT_NS_VETH" name eth0
    ip -n "$RIGHT_NS" addr add 10.0.3.2/24 dev eth0
    ip -n "$RIGHT_NS" link set eth0 up
    ip -n "$RIGHT_NS" route add default via 10.0.3.15

    echo "netfilter-stage2c: isolated TAP topology ready"
    echo "left endpoint:  $LEFT_NS (10.0.2.2 via 10.0.2.15)"
    echo "right endpoint: $RIGHT_NS (10.0.3.2 via 10.0.3.15)"
    echo "QEMU TAPs: $LEFT_TAP, $RIGHT_TAP"
}

test_forwarding() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi

    run_ping "$LEFT_NS" 10.0.3.2 "left-to-right"
    run_ping "$RIGHT_NS" 10.0.2.2 "right-to-left"
    echo "netfilter-stage2c: bidirectional IPv4 forwarding passed"
}

test_icmp_masquerade() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi
    if ! command -v tcpdump >/dev/null 2>&1; then
        echo "tcpdump is required for NAT packet-header acceptance." >&2
        exit 1
    fi

    local capture
    local capture_pid
    capture=$(mktemp)
    trap 'rm -f "$capture"' RETURN

    # The bridge observes the packet after the router's right-hand egress.
    # Capture one Echo request while the endpoint test independently proves
    # the reverse mapping carried the Echo reply back to the left namespace.
    timeout 10 tcpdump -n -l -i "$RIGHT_BR" -c 1 'icmp[0] == 8' >"$capture" 2>&1 &
    capture_pid=$!
    sleep 0.2

    run_ping "$LEFT_NS" 10.0.3.2 "left-to-right MASQUERADE"
    wait "$capture_pid"
    cat "$capture"
    if ! grep -Eq '10\.0\.3\.15 > 10\.0\.3\.2: ICMP echo request' "$capture"; then
        echo "Stage 3 MASQUERADE source address was not observed on $RIGHT_BR." >&2
        return 1
    fi

    echo "netfilter-stage3: stateful ICMP MASQUERADE passed"
}

test_icmp_dnat() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi
    if ! command -v tcpdump >/dev/null 2>&1; then
        echo "tcpdump is required for NAT packet-header acceptance." >&2
        exit 1
    fi

    local capture
    local capture_pid
    capture=$(mktemp)
    trap 'rm -f "$capture"' RETURN

    # 10.0.2.15 is the virtual service address. A right-bridge capture must
    # show that PREROUTING DNAT selected the 10.0.3.2 backend.
    timeout 10 tcpdump -n -l -i "$RIGHT_BR" -c 1 'icmp[0] == 8' >"$capture" 2>&1 &
    capture_pid=$!
    sleep 0.2

    run_ping "$LEFT_NS" 10.0.2.15 "left-to-virtual-service DNAT"
    wait "$capture_pid"
    cat "$capture"
    if ! grep -Eq '10\.0\.2\.2 > 10\.0\.3\.2: ICMP echo request' "$capture"; then
        echo "Stage 3 DNAT backend packet was not observed on $RIGHT_BR." >&2
        return 1
    fi

    echo "netfilter-stage3: stateful ICMP DNAT passed"
}

test_icmp_forward_drop() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi

    local output
    echo "Testing FORWARD-chain ICMP DROP through Asterinas..."
    output=$(ip netns exec "$LEFT_NS" ping -n -c 4 -W 1 10.0.3.2 2>&1 || true)
    printf '%s\n' "$output"
    if ! grep -q '100% packet loss' <<<"$output"; then
        echo "Stage 3 FORWARD DROP did not block the matching ICMP flow." >&2
        return 1
    fi

    echo "netfilter-stage3: FORWARD ICMP DROP passed"
}

test_tcp_masquerade() {
    require_stage4_dependencies
    local capture server_pid capture_pid output ports
    capture=$(mktemp)
    trap 'rm -f "$capture" "$capture.server"' RETURN

    ip netns exec "$RIGHT_NS" python3 -c '
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.0.3.2", 9000))
s.listen(2)
for _ in range(2):
    c, _ = s.accept()
    data = c.recv(64)
    c.sendall(data)
    c.close()
s.close()
' >"$capture.server" 2>&1 &
    server_pid=$!
    tcpdump -n -l -i "$RIGHT_BR" -c 2 'tcp dst port 9000 and tcp[tcpflags] & tcp-syn != 0' >"$capture" 2>&1 &
    capture_pid=$!
    sleep 0.2

    echo "Testing two TCP MASQUERADE flows through Asterinas..."
    if ! output=$(ip netns exec "$LEFT_NS" python3 -c '
import socket
for port in (31001, 31002):
    s = socket.socket()
    s.settimeout(5)
    s.bind(("10.0.2.2", port))
    s.connect(("10.0.3.2", 9000))
    payload = ("stage4-tcp-%d" % port).encode()
    s.sendall(payload)
    assert s.recv(64) == payload
    s.close()
print("stage4 TCP application replies passed")
' 2>&1); then
        printf '%s\n' "$output"
        # Do not wait here: a netns child can survive the parent and make a
        # failed acceptance test hang indefinitely. These namespaces are
        # dedicated to this harness, so terminate their test children now.
        kill "$server_pid" "$capture_pid" 2>/dev/null || true
        for pid in $(ip netns pids "$RIGHT_NS" 2>/dev/null); do
            kill "$pid" 2>/dev/null || true
        done
        cat "$capture.server" >&2 || true
        cat "$capture" >&2 || true
        return 1
    fi
    printf '%s\n' "$output"
    wait "$server_pid"
    wait "$capture_pid"
    cat "$capture"

    if ! grep -Eq '10\.0\.3\.15\.[0-9]+ > 10\.0\.3\.2\.9000' "$capture"; then
        echo "Stage 4 TCP MASQUERADE source tuple was not observed on $RIGHT_BR." >&2
        return 1
    fi
    ports=$(grep -oE '10\.0\.3\.15\.[0-9]+' "$capture" | sort -u | wc -l)
    if [ "$ports" -lt 2 ]; then
        echo "Stage 4 TCP MASQUERADE did not allocate distinct translated ports." >&2
        return 1
    fi
    echo "netfilter-stage4: stateful TCP MASQUERADE passed"
}

test_udp_masquerade() {
    require_stage4_dependencies
    local capture server_pid capture_pid output
    capture=$(mktemp)
    trap 'rm -f "$capture" "$capture.server"' RETURN

    ip netns exec "$RIGHT_NS" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.3.2", 9001))
data, peer = s.recvfrom(64)
s.sendto(data, peer)
s.close()
' >"$capture.server" 2>&1 &
    server_pid=$!
    tcpdump -n -l -i "$RIGHT_BR" -c 1 'udp dst port 9001' >"$capture" 2>&1 &
    capture_pid=$!
    sleep 0.2

    echo "Testing UDP MASQUERADE through Asterinas..."
    if ! output=$(ip netns exec "$LEFT_NS" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.bind(("10.0.2.2", 32001))
payload = b"stage4-udp"
s.sendto(payload, ("10.0.3.2", 9001))
data, _ = s.recvfrom(64)
assert data == payload
print("stage4 UDP application reply passed")
' 2>&1); then
        printf '%s\n' "$output"
        # Failure diagnostics must not block on a lingering process in the
        # dedicated right-hand namespace.
        kill "$server_pid" "$capture_pid" 2>/dev/null || true
        for pid in $(ip netns pids "$RIGHT_NS" 2>/dev/null); do
            kill "$pid" 2>/dev/null || true
        done
        cat "$capture.server" >&2 || true
        cat "$capture" >&2 || true
        return 1
    fi
    printf '%s\n' "$output"
    wait "$server_pid"
    wait "$capture_pid"
    cat "$capture"

    if ! grep -Eq '10\.0\.3\.15\.[0-9]+ > 10\.0\.3\.2\.9001' "$capture"; then
        echo "Stage 4 UDP MASQUERADE source tuple was not observed on $RIGHT_BR." >&2
        return 1
    fi
    echo "netfilter-stage4: stateful UDP MASQUERADE passed"
}

test_tcp_dnat() {
    require_stage4_dependencies
    local capture server_pid capture_pid output
    capture=$(mktemp)
    trap 'rm -f "$capture" "$capture.server"' RETURN

    ip netns exec "$RIGHT_NS" python3 -c '
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.0.3.2", 9002))
s.listen(1)
c, _ = s.accept()
data = c.recv(64)
c.sendall(data)
c.close()
s.close()
' >"$capture.server" 2>&1 &
    server_pid=$!
    tcpdump -n -l -i "$RIGHT_BR" -c 1 'tcp dst port 9002 and tcp[tcpflags] & tcp-syn != 0' >"$capture" 2>&1 &
    capture_pid=$!
    sleep 0.2

    echo "Testing TCP port-DNAT through Asterinas..."
    if ! output=$(ip netns exec "$LEFT_NS" python3 -c '
import socket
s = socket.socket()
s.settimeout(5)
s.bind(("10.0.2.2", 33001))
s.connect(("10.0.2.15", 9002))
payload = b"stage4-dnat"
s.sendall(payload)
assert s.recv(64) == payload
s.close()
print("stage4 TCP DNAT application reply passed")
' 2>&1); then
        printf '%s\n' "$output"
        # Failure diagnostics must not block on a lingering process in the
        # dedicated right-hand namespace.
        kill "$server_pid" "$capture_pid" 2>/dev/null || true
        for pid in $(ip netns pids "$RIGHT_NS" 2>/dev/null); do
            kill "$pid" 2>/dev/null || true
        done
        cat "$capture.server" >&2 || true
        cat "$capture" >&2 || true
        return 1
    fi
    printf '%s\n' "$output"
    wait "$server_pid"
    wait "$capture_pid"
    cat "$capture"

    if ! grep -Eq '10\.0\.2\.2\.[0-9]+ > 10\.0\.3\.2\.9002' "$capture"; then
        echo "Stage 4 TCP DNAT backend tuple was not observed on $RIGHT_BR." >&2
        return 1
    fi
    echo "netfilter-stage4: stateful TCP DNAT passed"
}

test_tcp_conntrack_policy() {
    echo "Testing TCP NEW/ESTABLISHED FORWARD policy through Asterinas..."
    test_tcp_masquerade
    echo "netfilter-stage6: TCP conntrack NEW/ESTABLISHED policy passed"
}

require_stage4_dependencies() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi
    if ! command -v tcpdump >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
        echo "Stage 4 acceptance requires tcpdump and python3 on the Ubuntu host." >&2
        exit 1
    fi
}

run_ping() {
    local namespace=$1
    local destination=$2
    local direction=$3
    local output

    echo "Testing $direction ICMP through Asterinas..."
    if ! output=$(ip netns exec "$namespace" ping -n -c 4 -W 2 "$destination" 2>&1); then
        printf '%s\n' "$output"
        return 1
    fi
    printf '%s\n' "$output"
    if ! grep -q ' 0% packet loss' <<<"$output"; then
        echo "Stage 2C requires zero packet loss; $direction did not meet acceptance." >&2
        return 1
    fi
}

show() {
    ip -br link show "$LEFT_BR" "$RIGHT_BR" "$LEFT_TAP" "$RIGHT_TAP"
    ip -n "$LEFT_NS" -br addr show
    ip -n "$RIGHT_NS" -br addr show
    ip -n "$LEFT_NS" route show
    ip -n "$RIGHT_NS" route show
}

teardown() {
    # These names are fixed and owned solely by this acceptance harness.
    ip netns del "$LEFT_NS" 2>/dev/null || true
    ip netns del "$RIGHT_NS" 2>/dev/null || true
    ip link del "$LEFT_TAP" 2>/dev/null || true
    ip link del "$RIGHT_TAP" 2>/dev/null || true
    ip link del "$LEFT_BR" 2>/dev/null || true
    ip link del "$RIGHT_BR" 2>/dev/null || true
    echo "netfilter-stage2c: isolated TAP topology removed"
}

usage() {
    echo "Usage: $0 {setup|test|test-nat|test-dnat|test-forward-drop|test-tcp-nat|test-udp-nat|test-tcp-dnat|test-tcp-conntrack|show|teardown}" >&2
}

require_root
case "${1:-}" in
    setup) setup ;;
    test) test_forwarding ;;
    test-nat) test_icmp_masquerade ;;
    test-dnat) test_icmp_dnat ;;
    test-forward-drop) test_icmp_forward_drop ;;
    test-tcp-nat) test_tcp_masquerade ;;
    test-udp-nat) test_udp_masquerade ;;
    test-tcp-dnat) test_tcp_dnat ;;
    test-tcp-conntrack) test_tcp_conntrack_policy ;;
    show) show ;;
    teardown) teardown ;;
    *) usage; exit 2 ;;
esac
