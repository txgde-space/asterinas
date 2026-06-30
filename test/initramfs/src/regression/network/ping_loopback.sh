#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

echo "test_ping_loopback: checking ping command"
command -v ping

echo "test_ping_loopback: running raw ICMP ping to 127.0.0.1"
# regression initramfs 中的 /bin/ping 来自 BusyBox；它本身走 raw ICMP
# socket 路径，但不接受 iputils 风格的 "-I 127.0.0.1" 源地址写法。
ping -c 1 -W 2 127.0.0.1

echo "test_ping_loopback summary: raw socket ping command passed"
