// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/select.h>
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

static int poll_has_events(int fd, short events, short expected)
{
	struct pollfd poll_fd = { .fd = fd, .events = events };
	int ret = poll(&poll_fd, 1, 0);

	return ret == 1 && (poll_fd.revents & expected) == expected;
}

static int poll_has_no_read(int fd)
{
	struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
	int ret = poll(&poll_fd, 1, 0);

	return ret == 0 && poll_fd.revents == 0;
}

static int select_has_read(int fd, int expected_ready)
{
	fd_set read_fds;
	struct timeval timeout = { 0, 0 };
	int ret;

	FD_ZERO(&read_fds);
	FD_SET(fd, &read_fds);

	ret = select(fd + 1, &read_fds, NULL, NULL, &timeout);
	return ret == expected_ready &&
	       (FD_ISSET(fd, &read_fds) != 0) == expected_ready;
}

static int select_has_write(int fd)
{
	fd_set write_fds;
	struct timeval timeout = { 0, 0 };
	int ret;

	FD_ZERO(&write_fds);
	FD_SET(fd, &write_fds);

	ret = select(fd + 1, NULL, &write_fds, NULL, &timeout);
	return ret == 1 && FD_ISSET(fd, &write_fds);
}

static int epoll_has_events(int fd, uint32_t events, uint32_t expected)
{
	int epoll_fd = CHECK(epoll_create1(0));
	struct epoll_event event = { .events = events, .data.fd = fd };
	struct epoll_event actual = { 0 };
	int ret;

	CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
	ret = epoll_wait(epoll_fd, &actual, 1, 0);
	CHECK(close(epoll_fd));

	return ret == 1 && (actual.events & expected) == expected;
}

static int epoll_has_no_read(int fd)
{
	int epoll_fd = CHECK(epoll_create1(0));
	struct epoll_event event = { .events = EPOLLIN, .data.fd = fd };
	struct epoll_event actual = { 0 };
	int ret;

	CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
	ret = epoll_wait(epoll_fd, &actual, 1, 0);
	CHECK(close(epoll_fd));

	return ret == 0;
}

static int new_loopback_listener(struct sockaddr_in *listen_addr)
{
	socklen_t listen_addrlen = sizeof(*listen_addr);
	int listen_fd = CHECK(socket(AF_INET, SOCK_STREAM, 0));

	init_loopback_addr(listen_addr, 0);
	CHECK(bind(listen_fd, (struct sockaddr *)listen_addr,
		   sizeof(*listen_addr)));
	CHECK(getsockname(listen_fd, (struct sockaddr *)listen_addr,
			  &listen_addrlen));
	CHECK(listen(listen_fd, 2));

	return listen_fd;
}

static int connect_loopback(const struct sockaddr_in *listen_addr)
{
	int connect_fd = CHECK(socket(AF_INET, SOCK_STREAM, 0));

	CHECK(connect(connect_fd, (const struct sockaddr *)listen_addr,
		      sizeof(*listen_addr)));

	return connect_fd;
}

FN_TEST(tcp_listener_readiness)
{
	struct sockaddr_in listen_addr;
	int listen_fd = new_loopback_listener(&listen_addr);

	/* Linux 语义：没有待 accept 连接时，监听 socket 不应报告可读。 */
	TEST_RES(poll_has_no_read(listen_fd), _ret);
	TEST_RES(select_has_read(listen_fd, 0), _ret);
	TEST_RES(epoll_has_no_read(listen_fd), _ret);

	int connect_fd = connect_loopback(&listen_addr);

	TEST_RES(poll_has_events(listen_fd, POLLIN, POLLIN), _ret);
	TEST_RES(select_has_read(listen_fd, 1), _ret);
	TEST_RES(epoll_has_events(listen_fd, EPOLLIN, EPOLLIN), _ret);

	int accept_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));

	TEST_SUCC(close(accept_fd));
	TEST_SUCC(close(connect_fd));
	TEST_SUCC(close(listen_fd));
}
END_TEST()

FN_TEST(tcp_connected_readiness)
{
	struct sockaddr_in listen_addr;
	char byte = 'r';
	int listen_fd = new_loopback_listener(&listen_addr);
	int connect_fd = connect_loopback(&listen_addr);
	int accept_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));

	TEST_RES(poll_has_events(accept_fd, POLLIN | POLLOUT, POLLOUT), _ret);
	TEST_RES(select_has_write(accept_fd), _ret);
	TEST_RES(epoll_has_events(accept_fd, EPOLLIN | EPOLLOUT, EPOLLOUT),
		 _ret);

	TEST_RES(write(connect_fd, &byte, sizeof(byte)), _ret == sizeof(byte));

	TEST_RES(poll_has_events(accept_fd, POLLIN | POLLOUT,
				 POLLIN | POLLOUT),
		 _ret);
	TEST_RES(select_has_read(accept_fd, 1), _ret);
	TEST_RES(epoll_has_events(accept_fd, EPOLLIN | EPOLLOUT,
				  EPOLLIN | EPOLLOUT),
		 _ret);

	TEST_RES(read(accept_fd, &byte, sizeof(byte)),
		 _ret == sizeof(byte) && byte == 'r');

	TEST_SUCC(close(accept_fd));
	TEST_SUCC(close(connect_fd));
	TEST_SUCC(close(listen_fd));
}
END_TEST()

FN_TEST(udp_datagram_readiness)
{
	struct sockaddr_in recv_addr;
	socklen_t recv_addrlen = sizeof(recv_addr);
	char send_byte = 'u';
	char recv_byte = 0;
	int recv_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int send_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));

	init_loopback_addr(&recv_addr, 0);
	TEST_SUCC(bind(recv_fd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)));
	TEST_SUCC(getsockname(recv_fd, (struct sockaddr *)&recv_addr,
			      &recv_addrlen));

	/* UDP socket 通常一直可写；只有收到数据后才应报告可读。 */
	TEST_RES(poll_has_events(recv_fd, POLLIN | POLLOUT, POLLOUT), _ret);
	TEST_RES(select_has_read(recv_fd, 0), _ret);
	TEST_RES(select_has_write(recv_fd), _ret);
	TEST_RES(epoll_has_events(recv_fd, EPOLLIN | EPOLLOUT, EPOLLOUT),
		 _ret);

	TEST_RES(sendto(send_fd, &send_byte, sizeof(send_byte), 0,
			(struct sockaddr *)&recv_addr, sizeof(recv_addr)),
		 _ret == sizeof(send_byte));

	TEST_RES(poll_has_events(recv_fd, POLLIN | POLLOUT,
				 POLLIN | POLLOUT),
		 _ret);
	TEST_RES(select_has_read(recv_fd, 1), _ret);
	TEST_RES(epoll_has_events(recv_fd, EPOLLIN | EPOLLOUT,
				  EPOLLIN | EPOLLOUT),
		 _ret);
	TEST_RES(read(recv_fd, &recv_byte, sizeof(recv_byte)),
		 _ret == sizeof(recv_byte) && recv_byte == 'u');

	TEST_SUCC(close(send_fd));
	TEST_SUCC(close(recv_fd));
}
END_TEST()
