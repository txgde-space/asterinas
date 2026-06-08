#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

echo "test_ping_loopback: checking ping command"
command -v ping

echo "test_ping_loopback: running ping -c 1 127.0.0.1"
# RAW_SOCKET_STAGE5: This is the command-level proof that the raw ICMP
# compatibility work supports a normal Linux-style ping workflow.
ping -c 1 -W 2 127.0.0.1

echo "test_ping_loopback summary: ping command passed"
