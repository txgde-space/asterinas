// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/test.h"

#define GUEST_PRIMARY_ADDR "10.0.2.15"
#define MIN_TCP_DEFAULT_BUF (256 * 1024)
#define MIN_UDP_DEFAULT_BUF (64 * 1024)

static void init_addr(struct sockaddr_in *addr, const char *ip, in_port_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = port;
	CHECK(inet_aton(ip, &addr->sin_addr));
}

static void init_loopback_addr(struct sockaddr_in *addr, in_port_t port)
{
	init_addr(addr, "127.0.0.1", port);
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

static int new_loopback_listener(struct sockaddr_in *listen_addr, int backlog)
{
	socklen_t listen_addrlen = sizeof(*listen_addr);
	int listen_fd = CHECK(socket(AF_INET, SOCK_STREAM, 0));

	init_loopback_addr(listen_addr, 0);
	CHECK(bind(listen_fd, (struct sockaddr *)listen_addr,
		   sizeof(*listen_addr)));
	CHECK(getsockname(listen_fd, (struct sockaddr *)listen_addr,
			  &listen_addrlen));
	CHECK(listen(listen_fd, backlog));

	return listen_fd;
}

static int connect_loopback(const struct sockaddr_in *listen_addr)
{
	int connect_fd = CHECK(socket(AF_INET, SOCK_STREAM, 0));

	CHECK(connect(connect_fd, (const struct sockaddr *)listen_addr,
		      sizeof(*listen_addr)));

	return connect_fd;
}

static int tcp_exchange_succeeds(int sender_fd, int receiver_fd, char expected)
{
	char actual = 0;

	if (write(sender_fd, &expected, sizeof(expected)) != sizeof(expected))
		return 0;

	if (read(receiver_fd, &actual, sizeof(actual)) != sizeof(actual))
		return 0;

	return actual == expected;
}

FN_TEST(tcp_inaddr_any_getsockname_and_connect)
{
	struct sockaddr_in bind_addr;
	struct sockaddr_in connect_addr;
	socklen_t bind_addrlen = sizeof(bind_addr);

	int listen_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
	init_addr(&bind_addr, "0.0.0.0", 0);
	TEST_SUCC(bind(listen_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)));
	TEST_SUCC(getsockname(listen_fd, (struct sockaddr *)&bind_addr,
			      &bind_addrlen));
	TEST_RES(bind_addr.sin_family, _ret == AF_INET);
	TEST_RES(bind_addr.sin_addr.s_addr, _ret == htonl(INADDR_ANY));
	TEST_RES(bind_addr.sin_port, _ret != 0);
	TEST_SUCC(listen(listen_fd, 1));

	int connect_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
	init_addr(&connect_addr, GUEST_PRIMARY_ADDR, bind_addr.sin_port);
	TEST_ERRNO(connect(connect_fd, (struct sockaddr *)&connect_addr,
			   sizeof(connect_addr)),
		   EINPROGRESS);

	struct pollfd poll_fd = { .fd = listen_fd, .events = POLLIN };
	TEST_RES(poll(&poll_fd, 1, 1000), _ret == 1 && (poll_fd.revents & POLLIN));

	int accepted_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));
	TEST_RES(tcp_exchange_succeeds(connect_fd, accepted_fd, 'a'), _ret);

	TEST_SUCC(close(accepted_fd));
	TEST_SUCC(close(connect_fd));
	TEST_SUCC(close(listen_fd));
}
END_TEST()

FN_TEST(udp_inaddr_any_receives_datagram)
{
	struct sockaddr_in bind_addr;
	struct sockaddr_in send_addr;
	socklen_t bind_addrlen = sizeof(bind_addr);
	char send_byte = 'u';
	char recv_byte = 0;

	int recv_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	init_addr(&bind_addr, "0.0.0.0", 0);
	TEST_SUCC(bind(recv_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)));
	TEST_SUCC(getsockname(recv_fd, (struct sockaddr *)&bind_addr,
			      &bind_addrlen));
	TEST_RES(bind_addr.sin_addr.s_addr, _ret == htonl(INADDR_ANY));

	int send_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	init_addr(&send_addr, GUEST_PRIMARY_ADDR, bind_addr.sin_port);
	TEST_RES(sendto(send_fd, &send_byte, sizeof(send_byte), 0,
			(struct sockaddr *)&send_addr, sizeof(send_addr)),
		 _ret == sizeof(send_byte));

	struct pollfd poll_fd = { .fd = recv_fd, .events = POLLIN };
	TEST_RES(poll(&poll_fd, 1, 1000), _ret == 1 && (poll_fd.revents & POLLIN));
	TEST_RES(read(recv_fd, &recv_byte, sizeof(recv_byte)),
		 _ret == sizeof(recv_byte) && recv_byte == 'u');

	TEST_SUCC(close(send_fd));
	TEST_SUCC(close(recv_fd));
}
END_TEST()

FN_TEST(tcp_listen_autobinds_inaddr_any)
{
	struct sockaddr_in listen_addr;
	struct sockaddr_in connect_addr;
	socklen_t listen_addrlen = sizeof(listen_addr);

	int listen_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
	TEST_SUCC(listen(listen_fd, 1));
	TEST_SUCC(getsockname(listen_fd, (struct sockaddr *)&listen_addr,
			      &listen_addrlen));
	TEST_RES(listen_addr.sin_family, _ret == AF_INET);
	TEST_RES(listen_addr.sin_addr.s_addr, _ret == htonl(INADDR_ANY));
	TEST_RES(listen_addr.sin_port, _ret != 0);

	int connect_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
	init_addr(&connect_addr, GUEST_PRIMARY_ADDR, listen_addr.sin_port);
	TEST_ERRNO(connect(connect_fd, (struct sockaddr *)&connect_addr,
			   sizeof(connect_addr)),
		   EINPROGRESS);

	struct pollfd poll_fd = { .fd = listen_fd, .events = POLLIN };
	TEST_RES(poll(&poll_fd, 1, 1000), _ret == 1 && (poll_fd.revents & POLLIN));

	int accepted_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));
	TEST_RES(tcp_exchange_succeeds(connect_fd, accepted_fd, 'l'), _ret);

	TEST_SUCC(close(accepted_fd));
	TEST_SUCC(close(connect_fd));
	TEST_SUCC(close(listen_fd));
}
END_TEST()

FN_TEST(loopback_tcp_and_udp_work)
{
	struct sockaddr_in listen_addr;
	struct sockaddr_in recv_addr;
	socklen_t recv_addrlen = sizeof(recv_addr);
	char send_byte = 'd';
	char recv_byte = 0;

	int listen_fd = new_loopback_listener(&listen_addr, 1);
	int connect_fd = connect_loopback(&listen_addr);
	int accepted_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));
	TEST_RES(tcp_exchange_succeeds(connect_fd, accepted_fd, 't'), _ret);
	TEST_SUCC(close(accepted_fd));
	TEST_SUCC(close(connect_fd));
	TEST_SUCC(close(listen_fd));

	int recv_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int send_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	init_loopback_addr(&recv_addr, 0);
	TEST_SUCC(bind(recv_fd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)));
	TEST_SUCC(getsockname(recv_fd, (struct sockaddr *)&recv_addr,
			      &recv_addrlen));
	TEST_RES(sendto(send_fd, &send_byte, sizeof(send_byte), 0,
			(struct sockaddr *)&recv_addr, sizeof(recv_addr)),
		 _ret == sizeof(send_byte));
	TEST_RES(read(recv_fd, &recv_byte, sizeof(recv_byte)),
		 _ret == sizeof(recv_byte) && recv_byte == 'd');
	TEST_SUCC(close(send_fd));
	TEST_SUCC(close(recv_fd));
}
END_TEST()

FN_TEST(listener_accepts_sequential_connections)
{
	struct sockaddr_in listen_addr;
	int listen_fd = new_loopback_listener(&listen_addr, 3);

	for (int i = 0; i < 3; i++) {
		char expected = '0' + i;
		int connect_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
		TEST_SUCC(connect(connect_fd, (struct sockaddr *)&listen_addr,
				  sizeof(listen_addr)));

		struct pollfd poll_fd = { .fd = listen_fd, .events = POLLIN };
		TEST_RES(poll(&poll_fd, 1, 1000),
			 _ret == 1 && (poll_fd.revents & POLLIN));

		int accepted_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));
		TEST_RES(tcp_exchange_succeeds(connect_fd, accepted_fd, expected),
			 _ret);
		TEST_SUCC(close(accepted_fd));
		TEST_SUCC(close(connect_fd));
	}

	TEST_SUCC(close(listen_fd));
}
END_TEST()

FN_TEST(socket_readiness_matches_common_service_states)
{
	struct sockaddr_in listen_addr;
	char byte = 'r';
	int listen_fd = new_loopback_listener(&listen_addr, 2);

	TEST_RES(poll_has_no_read(listen_fd), _ret);
	TEST_RES(select_has_read(listen_fd, 0), _ret);
	TEST_RES(epoll_has_no_read(listen_fd), _ret);

	int connect_fd = connect_loopback(&listen_addr);
	TEST_RES(poll_has_events(listen_fd, POLLIN, POLLIN), _ret);
	TEST_RES(select_has_read(listen_fd, 1), _ret);
	TEST_RES(epoll_has_events(listen_fd, EPOLLIN, EPOLLIN), _ret);

	int accepted_fd = TEST_SUCC(accept(listen_fd, NULL, NULL));
	TEST_RES(poll_has_events(accepted_fd, POLLIN | POLLOUT, POLLOUT), _ret);
	TEST_RES(select_has_write(accepted_fd), _ret);
	TEST_RES(epoll_has_events(accepted_fd, EPOLLIN | EPOLLOUT, EPOLLOUT),
		 _ret);

	TEST_RES(write(connect_fd, &byte, sizeof(byte)), _ret == sizeof(byte));
	TEST_RES(poll_has_events(accepted_fd, POLLIN | POLLOUT,
				 POLLIN | POLLOUT),
		 _ret);
	TEST_RES(select_has_read(accepted_fd, 1), _ret);
	TEST_RES(epoll_has_events(accepted_fd, EPOLLIN | EPOLLOUT,
				  EPOLLIN | EPOLLOUT),
		 _ret);
	TEST_RES(read(accepted_fd, &byte, sizeof(byte)),
		 _ret == sizeof(byte) && byte == 'r');

	TEST_SUCC(close(accepted_fd));
	TEST_SUCC(close(connect_fd));
	TEST_SUCC(close(listen_fd));
}
END_TEST()

FN_TEST(udp_readiness_matches_common_service_states)
{
	struct sockaddr_in recv_addr;
	socklen_t recv_addrlen = sizeof(recv_addr);
	char send_byte = 'q';
	char recv_byte = 0;
	int recv_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int send_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));

	init_loopback_addr(&recv_addr, 0);
	TEST_SUCC(bind(recv_fd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)));
	TEST_SUCC(getsockname(recv_fd, (struct sockaddr *)&recv_addr,
			      &recv_addrlen));

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
		 _ret == sizeof(recv_byte) && recv_byte == 'q');

	TEST_SUCC(close(send_fd));
	TEST_SUCC(close(recv_fd));
}
END_TEST()

FN_TEST(reuseaddr_allows_service_restart)
{
	struct sockaddr_in restart_addr;
	socklen_t restart_addrlen = sizeof(restart_addr);
	int option = 1;

	init_loopback_addr(&restart_addr, 0);

	int first_listener = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(setsockopt(first_listener, SOL_SOCKET, SO_REUSEADDR, &option,
			     sizeof(option)));
	TEST_SUCC(bind(first_listener, (struct sockaddr *)&restart_addr,
		       restart_addrlen));
	TEST_SUCC(getsockname(first_listener, (struct sockaddr *)&restart_addr,
			      &restart_addrlen));
	TEST_SUCC(listen(first_listener, 1));

	int client = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(connect(client, (struct sockaddr *)&restart_addr,
			  restart_addrlen));
	int accepted = TEST_SUCC(accept(first_listener, NULL, NULL));
	TEST_RES(tcp_exchange_succeeds(client, accepted, 's'), _ret);

	TEST_SUCC(close(accepted));
	TEST_SUCC(close(client));
	TEST_SUCC(close(first_listener));

	int second_listener = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(setsockopt(second_listener, SOL_SOCKET, SO_REUSEADDR, &option,
			     sizeof(option)));
	TEST_SUCC(bind(second_listener, (struct sockaddr *)&restart_addr,
		       restart_addrlen));
	TEST_SUCC(listen(second_listener, 1));
	TEST_SUCC(close(second_listener));
}
END_TEST()

FN_TEST(default_socket_buffers_cover_common_services)
{
	int tcp_fd = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	int udp_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	int optval = 0;
	socklen_t optlen = sizeof(optval);

	TEST_RES(getsockopt(tcp_fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen),
		 optlen == sizeof(optval) && optval >= MIN_TCP_DEFAULT_BUF);
	optlen = sizeof(optval);
	TEST_RES(getsockopt(tcp_fd, SOL_SOCKET, SO_RCVBUF, &optval, &optlen),
		 optlen == sizeof(optval) && optval >= MIN_TCP_DEFAULT_BUF);

	optlen = sizeof(optval);
	TEST_RES(getsockopt(udp_fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen),
		 optlen == sizeof(optval) && optval >= MIN_UDP_DEFAULT_BUF);
	optlen = sizeof(optval);
	TEST_RES(getsockopt(udp_fd, SOL_SOCKET, SO_RCVBUF, &optval, &optlen),
		 optlen == sizeof(optval) && optval >= MIN_UDP_DEFAULT_BUF);

	TEST_SUCC(close(udp_fd));
	TEST_SUCC(close(tcp_fd));
}
END_TEST()

FN_TEST(ipv6_boundary_is_explicit)
{
	TEST_ERRNO(socket(AF_INET6, SOCK_STREAM, 0), EAFNOSUPPORT);
	TEST_ERRNO(socket(AF_INET6, SOCK_DGRAM, 0), EAFNOSUPPORT);
}
END_TEST()
