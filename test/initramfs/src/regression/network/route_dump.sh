#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

echo "test_ipv4_route_dump: querying NETLINK_ROUTE with ip -4 route"
routes=$(ip -4 route)
printf '%s\n' "$routes"

test -n "$routes"
printf '%s\n' "$routes" | grep -q 'default'

echo "test_ipv4_route_dump summary: RTM_GETROUTE dump passed"
