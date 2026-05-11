// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/test.h"

#define GUEST_VIRTIO_ADDR "10.0.2.15"

static void init_addr(struct sockaddr_in *addr, const char *ip, in_port_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = port;
	CHECK(inet_aton(ip, &addr->sin_addr));
}

FN_TEST(tcp_listen_autobinds_inaddr_any)
{
	struct sockaddr_in listen_addr;
	struct sockaddr_in connect_addr;
	socklen_t listen_addrlen = sizeof(listen_addr);
	char buf = 'l';

	int listen_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
	TEST_SUCC(listen(listen_fd, 1));
	TEST_SUCC(getsockname(listen_fd, (struct sockaddr *)&listen_addr,
			      &listen_addrlen));
	TEST_RES(listen_addr.sin_family, _ret == AF_INET);
	TEST_RES(listen_addr.sin_addr.s_addr, _ret == htonl(INADDR_ANY));
	TEST_RES(listen_addr.sin_port, _ret != 0);

	int connect_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
	init_addr(&connect_addr, GUEST_VIRTIO_ADDR, listen_addr.sin_port);
	TEST_ERRNO(connect(connect_fd, (struct sockaddr *)&connect_addr,
			   sizeof(connect_addr)),
		   EINPROGRESS);

	struct pollfd poll_fd = { .fd = listen_fd, .events = POLLIN };
	TEST_RES(poll(&poll_fd, 1, 1000), _ret == 1 && (poll_fd.revents & POLLIN));

	int accepted_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));
	TEST_RES(write(connect_fd, &buf, sizeof(buf)), _ret == sizeof(buf));
	TEST_RES(read(accepted_fd, &buf, sizeof(buf)),
		 _ret == sizeof(buf) && buf == 'l');

	TEST_SUCC(close(accepted_fd));
	TEST_SUCC(close(connect_fd));
	TEST_SUCC(close(listen_fd));
}
END_TEST()
