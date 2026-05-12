// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/test.h"

static void init_loopback_addr(struct sockaddr_in *addr, in_port_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = port;
	CHECK(inet_aton("127.0.0.1", &addr->sin_addr));
}

FN_TEST(tcp_loopback_accepts_connection)
{
	struct sockaddr_in listen_addr;
	socklen_t listen_addrlen = sizeof(listen_addr);
	char byte = 't';

	int listen_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	init_loopback_addr(&listen_addr, 0);
	TEST_SUCC(bind(listen_fd, (struct sockaddr *)&listen_addr,
		       sizeof(listen_addr)));
	TEST_SUCC(getsockname(listen_fd, (struct sockaddr *)&listen_addr,
			      &listen_addrlen));
	TEST_SUCC(listen(listen_fd, 1));

	int connect_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(connect(connect_fd, (struct sockaddr *)&listen_addr,
			  sizeof(listen_addr)));

	struct pollfd poll_fd = { .fd = listen_fd, .events = POLLIN };
	TEST_RES(poll(&poll_fd, 1, 1000),
		 _ret == 1 && (poll_fd.revents & POLLIN));

	int accepted_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));
	TEST_RES(write(connect_fd, &byte, sizeof(byte)), _ret == sizeof(byte));
	TEST_RES(read(accepted_fd, &byte, sizeof(byte)),
		 _ret == sizeof(byte) && byte == 't');

	TEST_SUCC(close(accepted_fd));
	TEST_SUCC(close(connect_fd));
	TEST_SUCC(close(listen_fd));
}
END_TEST()

FN_TEST(udp_loopback_receives_datagram)
{
	struct sockaddr_in recv_addr;
	socklen_t recv_addrlen = sizeof(recv_addr);
	char send_buf = 'u';
	char recv_buf = 0;

	int recv_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	init_loopback_addr(&recv_addr, 0);
	TEST_SUCC(bind(recv_fd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)));
	TEST_SUCC(getsockname(recv_fd, (struct sockaddr *)&recv_addr,
			      &recv_addrlen));

	int send_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	TEST_RES(sendto(send_fd, &send_buf, sizeof(send_buf), 0,
			(struct sockaddr *)&recv_addr, sizeof(recv_addr)),
		 _ret == sizeof(send_buf));

	struct pollfd poll_fd = { .fd = recv_fd, .events = POLLIN };
	TEST_RES(poll(&poll_fd, 1, 1000),
		 _ret == 1 && (poll_fd.revents & POLLIN));
	TEST_RES(read(recv_fd, &recv_buf, sizeof(recv_buf)),
		 _ret == sizeof(recv_buf) && recv_buf == 'u');

	TEST_SUCC(close(send_fd));
	TEST_SUCC(close(recv_fd));
}
END_TEST()
