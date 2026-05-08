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

FN_TEST(tcp_inaddr_any_accepts_virtio_addr)
{
	struct sockaddr_in bind_addr;
	struct sockaddr_in connect_addr;
	struct sockaddr_in accepted_addr;
	socklen_t bind_addrlen = sizeof(bind_addr);
	socklen_t accepted_addrlen = sizeof(accepted_addr);
	char buf = 'a';

	int listen_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
	init_addr(&bind_addr, "0.0.0.0", 0);
	TEST_SUCC(bind(listen_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)));
	TEST_SUCC(getsockname(listen_fd, (struct sockaddr *)&bind_addr, &bind_addrlen));
	TEST_SUCC(listen(listen_fd, 1));

	int connect_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
	init_addr(&connect_addr, GUEST_VIRTIO_ADDR, bind_addr.sin_port);
	TEST_ERRNO(connect(connect_fd, (struct sockaddr *)&connect_addr,
			   sizeof(connect_addr)),
		   EINPROGRESS);

	struct pollfd poll_fd = { .fd = listen_fd, .events = POLLIN };
	TEST_RES(poll(&poll_fd, 1, 1000), _ret == 1 && (poll_fd.revents & POLLIN));

	int accepted_fd = TEST_SUCC(accept(listen_fd, (struct sockaddr *)&accepted_addr,
					   &accepted_addrlen));
	TEST_RES(write(connect_fd, &buf, sizeof(buf)), _ret == sizeof(buf));
	TEST_RES(read(accepted_fd, &buf, sizeof(buf)), _ret == sizeof(buf) && buf == 'a');

	TEST_SUCC(close(accepted_fd));
	TEST_SUCC(close(connect_fd));
	TEST_SUCC(close(listen_fd));
}
END_TEST()

FN_TEST(udp_inaddr_any_receives_virtio_addr)
{
	struct sockaddr_in bind_addr;
	struct sockaddr_in send_addr;
	socklen_t bind_addrlen = sizeof(bind_addr);
	char send_buf = 'u';
	char recv_buf = 0;

	int recv_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	init_addr(&bind_addr, "0.0.0.0", 0);
	TEST_SUCC(bind(recv_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)));
	TEST_SUCC(getsockname(recv_fd, (struct sockaddr *)&bind_addr, &bind_addrlen));

	int send_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	init_addr(&send_addr, GUEST_VIRTIO_ADDR, bind_addr.sin_port);
	TEST_RES(sendto(send_fd, &send_buf, sizeof(send_buf), 0,
			(struct sockaddr *)&send_addr, sizeof(send_addr)),
		 _ret == sizeof(send_buf));

	struct pollfd poll_fd = { .fd = recv_fd, .events = POLLIN };
	TEST_RES(poll(&poll_fd, 1, 1000), _ret == 1 && (poll_fd.revents & POLLIN));
	TEST_RES(read(recv_fd, &recv_buf, sizeof(recv_buf)),
		 _ret == sizeof(recv_buf) && recv_buf == 'u');

	TEST_SUCC(close(send_fd));
	TEST_SUCC(close(recv_fd));
}
END_TEST()
