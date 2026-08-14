#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

echo "test_ipv4_route_dump: querying NETLINK_ROUTE with ip -4 route"
routes=$(ip -4 route)
printf '%s\n' "$routes"

test -n "$routes"
printf '%s\n' "$routes" | grep -q 'default'

echo "test_ipv4_route_dump summary: RTM_GETROUTE dump passed"

echo "test_ipv6_route_dump: querying NETLINK_ROUTE with ip -6 route"
ipv6_routes=$(ip -6 route)
printf '%s\n' "$ipv6_routes"

test -n "$ipv6_routes"
# IPv6 阶段的网络接口使用确定性的 ULA 前缀。
printf '%s\n' "$ipv6_routes" | grep -Eq 'fd00:(0:){2}[0-9]+::/64'
printf '%s\n' "$ipv6_routes" | grep -q 'default'

echo "test_ipv6_route_dump summary: IPv6 RTM_GETROUTE dump passed"

echo "test_ipv6_addr_dump: querying NETLINK_ROUTE with ip -6 addr"
ipv6_addrs=$(ip -6 addr show)
printf '%s\n' "$ipv6_addrs"

test -n "$ipv6_addrs"
printf '%s\n' "$ipv6_addrs" | grep -Eq 'fd00:(0:){2}[0-9]+::15/64'
printf '%s\n' "$ipv6_addrs" | grep -q 'inet6 ::1/128'

echo "test_ipv6_addr_dump summary: IPv6 RTM_GETADDR dump passed"
