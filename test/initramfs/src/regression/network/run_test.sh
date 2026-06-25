#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

./tcp_server &
sleep 0.2
./tcp_client

./udp_server &
sleep 0.2
./udp_client

./unix_server &
sleep 0.2
./unix_client

./linux_socket_compat_common
./linux_socket_compat
./icmp_raw_socket
./netfilter_rules
sh ./ping_loopback.sh
./listen_autobind
./listen_backlog
./inaddr_any
./getsockname_any
./localhost_loopback
./tcp_accept_model
./ipv6_any
./privileged_ports
./send_buf_full
./socket_buffer_defaults
./sendmmsg
./socketpair
./sockoption
./sockoption_unix
./tcp_err
./tcp_poll
./socket_readiness
./tcp_reuseaddr
./tcp_wrapped_buffer_io
./udp_broadcast
./udp_err
./unix_datagram_err
./unix_seqpacket_err
./unix_stream_err

./netlink_route
./rtnl_err
./uevent_err
