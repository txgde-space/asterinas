#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0

# 隔离 Asterinas 路由器拓扑使用的可逆宿主机上行链路。
#
# 演示 guest 有两个 TAP 接口。第一个接口使用左侧命名空间
#（10.0.2.2 / fd00:0:0:2::2）作为网关。此辅助脚本把该命名空间变为小型临时
# NAT 网关，而不修改 guest 内核或用户的常规 Ubuntu 路由。右侧隔离网络保留
# 经 Asterinas 的显式路由，非本地目标则使用第二条 veth 通往 Ubuntu 宿主机默认上行。

set -euo pipefail

LEFT_NS=${NETFILTER_LEFT_NS:-as2left}
LEFT_BR=${NETFILTER_LEFT_BR:-as2br0}
UPLINK_IF=${UPLINK_IF:-}
UPLINK_IF6=${UPLINK_IF6:-${NETFILTER_UPLINK_IF6:-}}
ROOT_VETH=${NETFILTER_UPLINK_ROOT_VETH:-as2uplink0}
NS_VETH=${NETFILTER_UPLINK_NS_VETH:-as2uplink1}
ROOT_IPV4=${NETFILTER_UPLINK_ROOT_IPV4:-172.31.255.1/30}
NS_IPV4=${NETFILTER_UPLINK_NS_IPV4:-172.31.255.2/30}
ROOT_IPV4_ADDR=${ROOT_IPV4%/*}
NS_IPV4_ADDR=${NS_IPV4%/*}
ROOT_IPV6=${NETFILTER_UPLINK_ROOT_IPV6:-fd00:ffff:2::1/64}
NS_IPV6=${NETFILTER_UPLINK_NS_IPV6:-fd00:ffff:2::2/64}
ROOT_IPV6_ADDR=${ROOT_IPV6%/*}
NS_IPV6_ADDR=${NS_IPV6%/*}
STATE_FILE=${NETFILTER_UPLINK_STATE:-stage-records/demo/netfilter-uplink.state}
FILTER_CHAIN=${NETFILTER_UPLINK_FILTER_CHAIN:-AST_UPLINK}
NAT_CHAIN=${NETFILTER_UPLINK_NAT_CHAIN:-AST_UPLINK_NAT}

state_dir() {
    dirname -- "$STATE_FILE"
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run this helper on Ubuntu with sudo." >&2
        exit 1
    fi
}

require_namespace() {
    ip netns list | awk '{print $1}' | grep -qx "$LEFT_NS" || {
        echo "Namespace $LEFT_NS does not exist; run stage2-router-topology.sh setup first." >&2
        exit 1
    }
}

detect_uplink() {
    if [ -n "$UPLINK_IF" ]; then
        ip link show "$UPLINK_IF" >/dev/null 2>&1 || {
            echo "UPLINK_IF=$UPLINK_IF does not exist." >&2
            exit 1
        }
    else
        UPLINK_IF=$(ip -4 route show default 2>/dev/null | awk 'NR == 1 {print $5}')
    fi
    if [ -z "$UPLINK_IF6" ]; then
        UPLINK_IF6=$(ip -6 route show default 2>/dev/null | awk 'NR == 1 {print $5}')
    else
        ip link show "$UPLINK_IF6" >/dev/null 2>&1 || {
            echo "UPLINK_IF6=$UPLINK_IF6 does not exist." >&2
            exit 1
        }
    fi
    [ -n "$UPLINK_IF" ] || {
        echo "No host IPv4 default route found; set UPLINK_IF (for example ens33)." >&2
        exit 1
    }
}

save_sysctl() {
    local key=$1
    local value
    value=$(sysctl -n "$key" 2>/dev/null || true)
    printf 'sysctl_%s=%s\n' "${key//./_}" "$value" >>"$STATE_FILE"
}

restore_sysctl() {
    local key=$1
    local name="sysctl_${key//./_}"
    local value
    value=$(awk -F= -v key="$name" '$1 == key {print substr($0, index($0, "=") + 1)}' "$STATE_FILE" 2>/dev/null | tail -n 1)
    [ -n "$value" ] && sysctl -q -w "$key=$value" || true
}

delete_jump() {
    local family=$1 table=$2 chain=$3 parent=$4
    local command=("$family")
    [ -n "$table" ] && command+=("$table")
    while "${command[@]}" -D "$parent" -j "$chain" >/dev/null 2>&1; do :; done
}

delete_chain() {
    local family=$1 table=$2 chain=$3
    local command=("$family")
    [ -n "$table" ] && command+=("$table")
    "${command[@]}" -F "$chain" >/dev/null 2>&1 || true
    "${command[@]}" -X "$chain" >/dev/null 2>&1 || true
}

delete_namespace_jump() {
    local family=$1
    while ip netns exec "$LEFT_NS" "$family" -D FORWARD -j "$FILTER_CHAIN" >/dev/null 2>&1; do :; done
}

setup_filter_chain() {
    local family=$1 table=$2 uplink=${3:-$UPLINK_IF}
    local command=("$family")
    [ -n "$table" ] && command+=("$table")
    "${command[@]}" -N "$FILTER_CHAIN" 2>/dev/null || true
    "${command[@]}" -F "$FILTER_CHAIN"
    "${command[@]}" -A "$FILTER_CHAIN" -i "$ROOT_VETH" -o "$uplink" -j ACCEPT
    "${command[@]}" -A "$FILTER_CHAIN" -i "$uplink" -o "$LEFT_BR" \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "${command[@]}" -A "$FILTER_CHAIN" -i "$uplink" -o "$ROOT_VETH" \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "${command[@]}" -I FORWARD 1 -j "$FILTER_CHAIN"
}

setup_nat_chain() {
    local family=$1 uplink=${2:-$UPLINK_IF}
    "$family" -t nat -N "$NAT_CHAIN" 2>/dev/null || true
    "$family" -t nat -F "$NAT_CHAIN"
    if [ "$family" = iptables ]; then
        "$family" -t nat -A "$NAT_CHAIN" -s 10.0.2.0/24 -o "$uplink" -j MASQUERADE
        "$family" -t nat -A "$NAT_CHAIN" -s 172.31.255.0/30 -o "$uplink" -j MASQUERADE
    else
        "$family" -t nat -A "$NAT_CHAIN" -s fd00:0:0:2::/64 -o "$uplink" -j MASQUERADE
        "$family" -t nat -A "$NAT_CHAIN" -s fd00:ffff:2::/64 -o "$uplink" -j MASQUERADE
    fi
    "$family" -t nat -I POSTROUTING 1 -j "$NAT_CHAIN"
}

setup_namespace_filter_chain() {
    local family=$1
    ip netns exec "$LEFT_NS" "$family" -N "$FILTER_CHAIN" 2>/dev/null || true
    ip netns exec "$LEFT_NS" "$family" -F "$FILTER_CHAIN"
    ip netns exec "$LEFT_NS" "$family" -A "$FILTER_CHAIN" \
        -i eth0 -o "$NS_VETH" -j ACCEPT
    ip netns exec "$LEFT_NS" "$family" -A "$FILTER_CHAIN" \
        -i "$NS_VETH" -o eth0 -m conntrack \
        --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip netns exec "$LEFT_NS" "$family" -I FORWARD 1 -j "$FILTER_CHAIN"
}

setup_ipv6_firewall() {
    if [ -z "$UPLINK_IF6" ] || ! command -v ip6tables >/dev/null 2>&1 || ! ip6tables -t nat -L >/dev/null 2>&1; then
        echo "IPv6 host default route or NAT table is unavailable; IPv6 remains outside the external probe scope." >&2
        return 1
    fi
    setup_filter_chain ip6tables "" "$UPLINK_IF6"
    setup_nat_chain ip6tables "$UPLINK_IF6"
    return 0
}

setup() {
    require_namespace
    detect_uplink
    mkdir -p "$(state_dir)"
    : >"$STATE_FILE"
    chmod 0644 "$STATE_FILE"
    printf 'uplink_if=%s\nuplink_if6=%s\nleft_ns=%s\nleft_br=%s\nroot_veth=%s\nns_veth=%s\n' \
        "$UPLINK_IF" "$UPLINK_IF6" "$LEFT_NS" "$LEFT_BR" "$ROOT_VETH" "$NS_VETH" >>"$STATE_FILE"

    for key in net.ipv4.ip_forward net.ipv6.conf.all.forwarding; do
        save_sysctl "$key"
    done
    sysctl -q -w net.ipv4.ip_forward=1
    sysctl -q -w net.ipv6.conf.all.forwarding=1

    if ip link show "$ROOT_VETH" >/dev/null 2>&1; then
        echo "Uplink veth $ROOT_VETH already exists; refreshing rules."
    else
        ip link add "$ROOT_VETH" type veth peer name "$NS_VETH"
        ip link set "$NS_VETH" netns "$LEFT_NS"
    fi
    ip addr replace "$ROOT_IPV4" dev "$ROOT_VETH"
    ip addr replace "$ROOT_IPV6" dev "$ROOT_VETH"
    ip link set "$ROOT_VETH" up
    # 连接跟踪恢复的返回流量以左侧 TAP 网桥上的 guest 为目标，
    # 而不是上行 veth 本身。
    ip route replace 10.0.2.0/24 dev "$LEFT_BR"
    ip -6 route replace fd00:0:0:2::/64 dev "$LEFT_BR"
    ip -n "$LEFT_NS" addr replace "$NS_IPV4" dev "$NS_VETH"
    ip -n "$LEFT_NS" -6 addr replace "$NS_IPV6" dev "$NS_VETH"
    ip -n "$LEFT_NS" link set "$NS_VETH" up

    ip netns exec "$LEFT_NS" sysctl -q -w net.ipv4.ip_forward=1
    ip netns exec "$LEFT_NS" sysctl -q -w net.ipv6.conf.all.forwarding=1
    ip -n "$LEFT_NS" route replace 10.0.3.0/24 via 10.0.2.15 dev eth0
    ip -n "$LEFT_NS" -6 route replace fd00:0:0:3::/64 via fd00:0:0:2::15 dev eth0
    ip -n "$LEFT_NS" route replace default via "$ROOT_IPV4_ADDR" dev "$NS_VETH"
    ip -n "$LEFT_NS" -6 route replace default via "$ROOT_IPV6_ADDR" dev "$NS_VETH"

    # 确保 dashboard 会话中断后重复调用配置仍然安全。
    delete_jump iptables "" "$FILTER_CHAIN" FORWARD
    delete_jump iptables -t nat "$NAT_CHAIN" POSTROUTING
    delete_namespace_jump iptables
    delete_jump ip6tables "" "$FILTER_CHAIN" FORWARD 2>/dev/null || true
    delete_jump ip6tables -t nat "$NAT_CHAIN" POSTROUTING 2>/dev/null || true
    delete_namespace_jump ip6tables 2>/dev/null || true
    setup_filter_chain iptables ""
    setup_nat_chain iptables
    setup_namespace_filter_chain iptables
    if ! setup_ipv6_firewall; then
        printf 'ipv6_nat=unavailable\n' >>"$STATE_FILE"
    else
        setup_namespace_filter_chain ip6tables
        printf 'ipv6_nat=enabled\n' >>"$STATE_FILE"
    fi
    printf 'configured=1\n' >>"$STATE_FILE"
    echo "Asterinas external IPv4 uplink ready via $UPLINK_IF."
    echo "Guest path: 10.0.2.15/fd00:0:0:2::15 -> $LEFT_NS -> $UPLINK_IF"
}

status() {
    require_namespace
    echo "--- uplink state ---"
    if [ -f "$STATE_FILE" ]; then cat "$STATE_FILE"; else echo "not configured"; fi
    echo "--- host route ---"
    ip -4 route show default || true
    ip -6 route show default || true
    echo "--- namespace addresses/routes ---"
    ip -n "$LEFT_NS" -br addr show "$NS_VETH" 2>/dev/null || true
    ip -n "$LEFT_NS" route show || true
    ip -n "$LEFT_NS" -6 route show || true
    echo "--- external probes from left namespace ---"
    ip netns exec "$LEFT_NS" ping -4 -n -c 1 -W 2 1.1.1.1 || true
}

test_one() {
    local target=$1
    ip netns exec "$LEFT_NS" ping -4 -n -c 2 -W 2 "$target"
}

test() {
    require_namespace
    echo "Testing IPv4 external path through the Asterinas left gateway..."
    test_one 1.1.1.1
}

teardown() {
    require_namespace
    if [ -f "$STATE_FILE" ]; then
        restore_sysctl net.ipv4.ip_forward
        restore_sysctl net.ipv6.conf.all.forwarding
    fi
    delete_jump iptables "" "$FILTER_CHAIN" FORWARD
    delete_jump iptables -t nat "$NAT_CHAIN" POSTROUTING
    delete_chain iptables "" "$FILTER_CHAIN"
    delete_chain iptables -t nat "$NAT_CHAIN"
    delete_namespace_jump iptables
    ip netns exec "$LEFT_NS" iptables -F "$FILTER_CHAIN" 2>/dev/null || true
    ip netns exec "$LEFT_NS" iptables -X "$FILTER_CHAIN" 2>/dev/null || true
    delete_jump ip6tables "" "$FILTER_CHAIN" FORWARD 2>/dev/null || true
    delete_jump ip6tables -t nat "$NAT_CHAIN" POSTROUTING 2>/dev/null || true
    delete_chain ip6tables "" "$FILTER_CHAIN"
    delete_chain ip6tables -t nat "$NAT_CHAIN"
    delete_namespace_jump ip6tables
    ip netns exec "$LEFT_NS" ip6tables -F "$FILTER_CHAIN" 2>/dev/null || true
    ip netns exec "$LEFT_NS" ip6tables -X "$FILTER_CHAIN" 2>/dev/null || true
    ip -n "$LEFT_NS" route replace default via 10.0.2.15 dev eth0 2>/dev/null || true
    ip -n "$LEFT_NS" -6 route replace default via fd00:0:0:2::15 dev eth0 2>/dev/null || true
    ip route del 10.0.2.0/24 dev "$LEFT_BR" 2>/dev/null || true
    ip -6 route del fd00:0:0:2::/64 dev "$LEFT_BR" 2>/dev/null || true
    ip -n "$LEFT_NS" link del "$NS_VETH" 2>/dev/null || true
    ip link del "$ROOT_VETH" 2>/dev/null || true
    rm -f "$STATE_FILE"
    echo "Asterinas external uplink removed."
}

require_root
case "${1:-status}" in
    setup) setup ;;
    status) status ;;
    test) test ;;
    test-ipv4) require_namespace; test_one 1.1.1.1 ;;
    teardown) teardown ;;
    *) echo "Usage: $0 {setup|status|test|test-ipv4|teardown}" >&2; exit 2 ;;
esac
