#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0

# 仅创建阶段 2C 转发验收使用的隔离宿主机拓扑。QEMU 持有两个 TAP 文件描述符，
# 端点命名空间提供两个独立 IPv4 主机。阶段 10C 还会为每个端点分配同链路 ULA 地址，
# 从而测试 guest 的以太网/NDP 路径，同时不宣称已经实现 IPv6 转发。

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
LEFT_IPV6=fd00:0:0:2::2
LEFT_ROUTER_IPV6=fd00:0:0:2::15
RIGHT_IPV6=fd00:0:0:3::2
RIGHT_ROUTER_IPV6=fd00:0:0:3::15

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
    ip -n "$LEFT_NS" -6 addr add "$LEFT_IPV6/64" dev eth0
    ip -n "$LEFT_NS" link set eth0 up
    ip -n "$LEFT_NS" route add default via 10.0.2.15
    ip -n "$LEFT_NS" -6 route add default via "$LEFT_ROUTER_IPV6"

    ip netns add "$RIGHT_NS"
    ip link add "$RIGHT_HOST_VETH" type veth peer name "$RIGHT_NS_VETH"
    ip link set "$RIGHT_NS_VETH" netns "$RIGHT_NS"
    ip link set "$RIGHT_HOST_VETH" master "$RIGHT_BR"
    ip link set "$RIGHT_HOST_VETH" up
    ip -n "$RIGHT_NS" link set lo up
    ip -n "$RIGHT_NS" link set "$RIGHT_NS_VETH" name eth0
    ip -n "$RIGHT_NS" addr add 10.0.3.2/24 dev eth0
    ip -n "$RIGHT_NS" -6 addr add "$RIGHT_IPV6/64" dev eth0
    ip -n "$RIGHT_NS" link set eth0 up
    ip -n "$RIGHT_NS" route add default via 10.0.3.15
    ip -n "$RIGHT_NS" -6 route add default via "$RIGHT_ROUTER_IPV6"

    echo "netfilter-stage2c: isolated TAP topology ready"
    echo "left endpoint:  $LEFT_NS (10.0.2.2 via 10.0.2.15)"
    echo "right endpoint: $RIGHT_NS (10.0.3.2 via 10.0.3.15)"
    echo "IPv6 peers:     $LEFT_IPV6 / $RIGHT_IPV6 (same-link guest addresses $LEFT_ROUTER_IPV6 / $RIGHT_ROUTER_IPV6)"
    echo "QEMU TAPs: $LEFT_TAP, $RIGHT_TAP"
}

test_ipv6_ethernet() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi

    local output
    echo "Testing IPv6 NDP + ICMPv6 echo on the left Ethernet link..."
    if ! output=$(ip netns exec "$LEFT_NS" ping -6 -n -c 4 -W 2 "$LEFT_ROUTER_IPV6" 2>&1); then
        printf '%s\n' "$output"
        return 1
    fi
    printf '%s\n' "$output"
    if ! grep -q ' 0% packet loss' <<<"$output"; then
        echo "Stage 10C requires zero packet loss for same-link ICMPv6." >&2
        return 1
    fi
    echo "netfilter-stage10c: IPv6 NDP + Ethernet ICMPv6 echo passed"
}

test_ipv6_forwarding() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi

    local left_output right_output
    echo "Testing bidirectional IPv6 forwarding through Asterinas..."
    if ! left_output=$(ip netns exec "$LEFT_NS" ping -6 -n -c 4 -W 2 "$RIGHT_IPV6" 2>&1); then
        printf '%s\n' "$left_output"
        return 1
    fi
    printf '%s\n' "$left_output"
    if ! grep -q ' 0% packet loss' <<<"$left_output"; then
        echo "Stage 10D left-to-right IPv6 forwarding did not meet acceptance." >&2
        return 1
    fi

    if ! right_output=$(ip netns exec "$RIGHT_NS" ping -6 -n -c 4 -W 2 "$LEFT_IPV6" 2>&1); then
        printf '%s\n' "$right_output"
        return 1
    fi
    printf '%s\n' "$right_output"
    if ! grep -q ' 0% packet loss' <<<"$right_output"; then
        echo "Stage 10D right-to-left IPv6 forwarding did not meet acceptance." >&2
        return 1
    fi

    echo "netfilter-stage10d: bidirectional IPv6 forwarding passed"
}

test_ipv6_forward_drop() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi

    local blocked_output allowed_output
    echo "Testing IPv6 ICMPv6 FORWARD DROP through Asterinas..."
    if blocked_output=$(ip netns exec "$LEFT_NS" ping -6 -n -c 2 -W 1 "$RIGHT_IPV6" 2>&1); then
        printf '%s\n' "$blocked_output"
        echo "Stage 11 expected the left-to-right IPv6 Echo Request to be dropped." >&2
        return 1
    fi
    printf '%s\n' "$blocked_output"
    if ! grep -q '100% packet loss' <<<"$blocked_output"; then
        echo "Stage 11 IPv6 FORWARD DROP did not produce complete packet loss." >&2
        return 1
    fi

    if ! allowed_output=$(ip netns exec "$RIGHT_NS" ping -6 -n -c 2 -W 2 "$LEFT_IPV6" 2>&1); then
        printf '%s\n' "$allowed_output"
        return 1
    fi
    printf '%s\n' "$allowed_output"
    if ! grep -q ' 0% packet loss' <<<"$allowed_output"; then
        echo "Stage 11 reverse IPv6 flow did not meet the acceptance policy." >&2
        return 1
    fi

    echo "netfilter-stage11: IPv6 ICMPv6 FORWARD DROP passed"
}

test_ipv6_snat() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi
    if ! command -v tcpdump >/dev/null 2>&1; then
        echo "tcpdump is required for Stage 12 IPv6 NAT acceptance." >&2
        exit 1
    fi

    local capture capture_pid output
    capture=$(mktemp)
    trap 'rm -f "$capture"' RETURN
    timeout 10 tcpdump -n -l -i "$RIGHT_BR" -c 1 'icmp6 and ip6[40] == 128' >"$capture" 2>&1 &
    capture_pid=$!
    sleep 0.2

    echo "Testing IPv6 MASQUERADE with stateful reverse mapping through Asterinas..."
    if ! output=$(ip netns exec "$LEFT_NS" ping -6 -n -c 4 -W 2 "$RIGHT_IPV6" 2>&1); then
        printf '%s\n' "$output"
        kill "$capture_pid" 2>/dev/null || true
        return 1
    fi
    printf '%s\n' "$output"
    wait "$capture_pid" || true
    cat "$capture"
    if ! grep -q ' 0% packet loss' <<<"$output"; then
        echo "Stage 12 IPv6 MASQUERADE reply did not reach the left endpoint." >&2
        return 1
    fi
    if ! grep -Eq 'fd00:0:0:3::15 > fd00:0:0:3::2' "$capture"; then
        echo "Stage 12 IPv6 MASQUERADE source address was not observed on $RIGHT_BR." >&2
        return 1
    fi
    echo "netfilter-stage12: stateful IPv6 MASQUERADE passed"
}

test_ipv6_dnat() {
    if ! topology_is_ready; then
        echo "Topology is incomplete; run '$0 teardown' and then '$0 setup'." >&2
        exit 1
    fi
    if ! command -v tcpdump >/dev/null 2>&1; then
        echo "tcpdump is required for Stage 12 IPv6 NAT acceptance." >&2
        exit 1
    fi

    local capture capture_pid output
    capture=$(mktemp)
    trap 'rm -f "$capture"' RETURN
    timeout 10 tcpdump -n -l -i "$RIGHT_BR" -c 1 'icmp6 and ip6[40] == 128' >"$capture" 2>&1 &
    capture_pid=$!
    sleep 0.2

    echo "Testing IPv6 PREROUTING DNAT to the right endpoint..."
    if ! output=$(ip netns exec "$LEFT_NS" ping -6 -n -c 4 -W 2 "$RIGHT_ROUTER_IPV6" 2>&1); then
        printf '%s\n' "$output"
        kill "$capture_pid" 2>/dev/null || true
        return 1
    fi
    printf '%s\n' "$output"
    wait "$capture_pid" || true
    cat "$capture"
    if ! grep -q ' 0% packet loss' <<<"$output"; then
        echo "Stage 12 IPv6 DNAT reverse mapping did not reach the left endpoint." >&2
        return 1
    fi
    if ! grep -Eq '> fd00:0:0:3::2' "$capture"; then
        echo "Stage 12 IPv6 DNAT backend address was not observed on $RIGHT_BR." >&2
        return 1
    fi
    echo "netfilter-stage12: stateful IPv6 DNAT passed"
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

    # 网桥观察数据包经过路由器右侧出口后的状态。捕获一个 Echo 请求，
    # 同时由端点测试独立证明反向映射把 Echo 回复带回左侧命名空间。
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

    # 10.0.2.15 是虚拟服务地址。右侧网桥抓包必须显示 PREROUTING DNAT
    # 选择了 10.0.3.2 后端。
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

    # 打开首个 TCP 流前预热两条 ARP 路径。否则新的 QEMU 实例必须在五秒应用超时
    # 已开始计时后解析两个邻居，使首个 SYN 测试在嵌套 VMware/KVM 宿主机上
    # 对时序产生不必要的敏感性。
    ip netns exec "$LEFT_NS" ping -4 -n -c 1 -W 1 10.0.3.2 \
        >/dev/null 2>&1 || true

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
    # 等待服务端完成 bind/listen，而不是依赖固定 sleep；启动失败时也能留下有用诊断。
    for _ in $(seq 1 40); do
        if ip netns exec "$RIGHT_NS" ss -H -ltn 'sport = :9000' \
            2>/dev/null | grep -q ':9000'; then
            break
        fi
        if ! kill -0 "$server_pid" 2>/dev/null; then
            cat "$capture.server" >&2 || true
            echo "TCP echo server exited before listening on 10.0.3.2:9000." >&2
            return 1
        fi
        sleep 0.05
    done
    tcpdump -n -l -i "$RIGHT_BR" -c 2 'tcp dst port 9000 and tcp[tcpflags] & tcp-syn != 0' >"$capture" 2>&1 &
    capture_pid=$!
    sleep 0.3

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
        # 此处不要等待：netns 子进程可能在父进程退出后继续存活，使失败的验收测试
        # 无限挂起。这些命名空间由当前测试框架独占，因此现在终止其中的测试子进程。
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
        # 失败诊断不能被专用右侧命名空间中的残留进程阻塞。
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
        # 失败诊断不能被专用右侧命名空间中的残留进程阻塞。
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
    local link
    for link in "$LEFT_BR" "$RIGHT_BR" "$LEFT_TAP" "$RIGHT_TAP"; do
        ip -br link show dev "$link"
    done
    ip -n "$LEFT_NS" -br addr show
    ip -n "$RIGHT_NS" -br addr show
    ip -n "$LEFT_NS" route show
    ip -n "$RIGHT_NS" route show
    ip -n "$LEFT_NS" -6 addr show
    ip -n "$RIGHT_NS" -6 addr show
    ip -n "$LEFT_NS" -6 route show
    ip -n "$RIGHT_NS" -6 route show
}

teardown() {
    # 这些名称固定且仅由当前验收框架持有。
    ip netns del "$LEFT_NS" 2>/dev/null || true
    ip netns del "$RIGHT_NS" 2>/dev/null || true
    ip link del "$LEFT_TAP" 2>/dev/null || true
    ip link del "$RIGHT_TAP" 2>/dev/null || true
    ip link del "$LEFT_BR" 2>/dev/null || true
    ip link del "$RIGHT_BR" 2>/dev/null || true
    echo "netfilter-stage2c: isolated TAP topology removed"
}

usage() {
    echo "Usage: $0 {setup|test|test-ipv6|test-ipv6-forward|test-ipv6-forward-drop|test-ipv6-snat|test-ipv6-dnat|test-nat|test-dnat|test-forward-drop|test-tcp-nat|test-udp-nat|test-tcp-dnat|show|teardown}" >&2
}

require_root
case "${1:-}" in
    setup) setup ;;
    test) test_forwarding ;;
    test-ipv6) test_ipv6_ethernet ;;
    test-ipv6-forward) test_ipv6_forwarding ;;
    test-ipv6-forward-drop) test_ipv6_forward_drop ;;
    test-ipv6-snat) test_ipv6_snat ;;
    test-ipv6-dnat) test_ipv6_dnat ;;
    test-nat) test_icmp_masquerade ;;
    test-dnat) test_icmp_dnat ;;
    test-forward-drop) test_icmp_forward_drop ;;
    test-tcp-nat) test_tcp_masquerade ;;
    test-udp-nat) test_udp_masquerade ;;
    test-tcp-dnat) test_tcp_dnat ;;
    show) show ;;
    teardown) teardown ;;
    *) usage; exit 2 ;;
esac
