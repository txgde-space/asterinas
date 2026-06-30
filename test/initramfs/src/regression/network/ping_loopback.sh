#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

echo "test_ping_loopback: checking ping command"
command -v ping

echo "test_ping_loopback: running raw ICMP ping to 127.0.0.1"
# 指标一的命令级验证：显式指定 loopback 源地址，触发 iputils ping 的
# raw ICMP socket 路径，证明内核 raw socket 能支撑真实 ping 命令。
ping -c 1 -W 1 -I 127.0.0.1 127.0.0.1

echo "test_ping_loopback summary: raw socket ping command passed"
