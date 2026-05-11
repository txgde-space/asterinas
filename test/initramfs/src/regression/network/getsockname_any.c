// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/test.h"

static void init_addr(struct sockaddr_in *addr, const char *ip, in_port_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = port;
	CHECK(inet_aton(ip, &addr->sin_addr));
}

#define CHECK_GETSOCKNAME_ADDR(fd, expected_ip, bound_port)                      \
	({                                                                      \
		struct sockaddr_in actual_addr;                                  \
		socklen_t actual_addrlen = sizeof(actual_addr);                  \
		struct in_addr expected_addr;                                    \
                                                                                \
		CHECK(inet_aton((expected_ip), &expected_addr));                 \
		TEST_SUCC(getsockname((fd), (struct sockaddr *)&actual_addr,     \
				      &actual_addrlen));                         \
		TEST_RES(actual_addr.sin_family, _ret == AF_INET);               \
		TEST_RES(actual_addr.sin_addr.s_addr,                            \
			 _ret == (int)expected_addr.s_addr);                     \
		TEST_RES(actual_addr.sin_port, _ret != 0);                       \
                                                                                \
		if (*(bound_port) == 0) {                                        \
			*(bound_port) = actual_addr.sin_port;                    \
		} else {                                                        \
			TEST_RES(actual_addr.sin_port, _ret == *(bound_port));   \
		}                                                               \
	})

FN_TEST(tcp_getsockname_keeps_inaddr_any)
{
	struct sockaddr_in bind_addr;
	in_port_t bound_port = 0;

	int fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	init_addr(&bind_addr, "0.0.0.0", 0);
	TEST_SUCC(bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)));

	CHECK_GETSOCKNAME_ADDR(fd, "0.0.0.0", &bound_port);
	TEST_SUCC(listen(fd, 1));
	CHECK_GETSOCKNAME_ADDR(fd, "0.0.0.0", &bound_port);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(udp_getsockname_keeps_inaddr_any)
{
	struct sockaddr_in bind_addr;
	in_port_t bound_port = 0;

	int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	init_addr(&bind_addr, "0.0.0.0", 0);
	TEST_SUCC(bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)));
	CHECK_GETSOCKNAME_ADDR(fd, "0.0.0.0", &bound_port);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(tcp_getsockname_keeps_loopback_addr)
{
	struct sockaddr_in bind_addr;
	in_port_t bound_port = 0;

	int fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	init_addr(&bind_addr, "127.0.0.1", 0);
	TEST_SUCC(bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)));
	CHECK_GETSOCKNAME_ADDR(fd, "127.0.0.1", &bound_port);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(udp_getsockname_keeps_loopback_addr)
{
	struct sockaddr_in bind_addr;
	in_port_t bound_port = 0;

	int fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	init_addr(&bind_addr, "127.0.0.1", 0);
	TEST_SUCC(bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)));
	CHECK_GETSOCKNAME_ADDR(fd, "127.0.0.1", &bound_port);

	TEST_SUCC(close(fd));
}
END_TEST()
