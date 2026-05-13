// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/test.h"

#define NUM_CLIENTS 3

static void init_loopback_addr(struct sockaddr_in *addr, in_port_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = port;
	CHECK(inet_aton("127.0.0.1", &addr->sin_addr));
}

FN_TEST(listener_accepts_sequential_connections)
{
	struct sockaddr_in listen_addr;
	socklen_t listen_addrlen = sizeof(listen_addr);

	int listen_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	init_loopback_addr(&listen_addr, 0);
	TEST_SUCC(bind(listen_fd, (struct sockaddr *)&listen_addr,
		       sizeof(listen_addr)));
	TEST_SUCC(getsockname(listen_fd, (struct sockaddr *)&listen_addr,
			      &listen_addrlen));
	TEST_SUCC(listen(listen_fd, NUM_CLIENTS));

	for (int i = 0; i < NUM_CLIENTS; i++) {
		char expected = 'a' + i;
		char actual = 0;

		int connect_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
		TEST_SUCC(connect(connect_fd, (struct sockaddr *)&listen_addr,
				  sizeof(listen_addr)));

		struct pollfd poll_fd = { .fd = listen_fd, .events = POLLIN };
		TEST_RES(poll(&poll_fd, 1, 1000),
			 _ret == 1 && (poll_fd.revents & POLLIN));

		int accepted_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));
		TEST_RES(write(connect_fd, &expected, sizeof(expected)),
			 _ret == sizeof(expected));
		TEST_RES(read(accepted_fd, &actual, sizeof(actual)),
			 _ret == sizeof(actual) && actual == expected);

		TEST_SUCC(close(accepted_fd));
		TEST_SUCC(close(connect_fd));
	}

	TEST_SUCC(close(listen_fd));
}
END_TEST()
