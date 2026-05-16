// SPDX-License-Identifier: MPL-2.0

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/test.h"

#define MIN_TCP_DEFAULT_BUF (256 * 1024)
#define MIN_UDP_DEFAULT_BUF (64 * 1024)

FN_TEST(tcp_default_buffers_support_http_response)
{
	int tcp_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	int sendbuf = 0;
	int recvbuf = 0;
	socklen_t optlen = sizeof(sendbuf);

	/* Asterinas 暂无自动调优，默认 TCP 缓冲必须直接覆盖常见 HTTP 首批响应。 */
	TEST_RES(getsockopt(tcp_fd, SOL_SOCKET, SO_SNDBUF, &sendbuf, &optlen),
		 optlen == sizeof(sendbuf) && sendbuf >= MIN_TCP_DEFAULT_BUF);

	optlen = sizeof(recvbuf);
	TEST_RES(getsockopt(tcp_fd, SOL_SOCKET, SO_RCVBUF, &recvbuf, &optlen),
		 optlen == sizeof(recvbuf) && recvbuf >= MIN_TCP_DEFAULT_BUF);

	TEST_SUCC(close(tcp_fd));
}
END_TEST()

FN_TEST(udp_default_buffers_cover_datagram_payload)
{
	int udp_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int sendbuf = 0;
	int recvbuf = 0;
	socklen_t optlen = sizeof(sendbuf);

	/* UDP 保持 64 KiB 级别，匹配单个 IPv4 datagram 的最大 payload 规模。 */
	TEST_RES(getsockopt(udp_fd, SOL_SOCKET, SO_SNDBUF, &sendbuf, &optlen),
		 optlen == sizeof(sendbuf) && sendbuf >= MIN_UDP_DEFAULT_BUF);

	optlen = sizeof(recvbuf);
	TEST_RES(getsockopt(udp_fd, SOL_SOCKET, SO_RCVBUF, &recvbuf, &optlen),
		 optlen == sizeof(recvbuf) && recvbuf >= MIN_UDP_DEFAULT_BUF);

	TEST_SUCC(close(udp_fd));
}
END_TEST()
