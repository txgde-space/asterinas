#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

./tcp_server &
sleep 0.2
./tcp_client

./udp_server &
sleep 0.2
./udp_client

rm -f /tmp/test.sock
./unix_server &
unix_server_ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
	if [ -e /tmp/test.sock ]; then
		unix_server_ready=1
		break
	fi
	sleep 0.1
done
if [ "$unix_server_ready" -ne 1 ]; then
	echo "unix_server did not create /tmp/test.sock" >&2
	exit 1
fi
./unix_client

./linux_socket_compat_common
./linux_socket_compat
./icmp_raw_socket
./netfilter_rules
sh ./ping_loopback.sh
sh ./route_dump.sh
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
