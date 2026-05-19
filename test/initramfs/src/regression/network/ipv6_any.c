// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../common/test.h"

FN_TEST(ipv6_tcp_socket_is_not_supported)
{
	/* 当前网络栈没有 IPv6 数据面，不能让 [::] bind 表现成半可用状态。 */
	TEST_ERRNO(socket(AF_INET6, SOCK_STREAM, 0), EAFNOSUPPORT);
}
END_TEST()

FN_TEST(ipv6_udp_socket_is_not_supported)
{
	/* UDP 同样保持显式 EAFNOSUPPORT，用户态可以可靠回退到 IPv4。 */
	TEST_ERRNO(socket(AF_INET6, SOCK_DGRAM, 0), EAFNOSUPPORT);
}
END_TEST()
