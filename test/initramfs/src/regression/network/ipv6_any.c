// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/errqueue.h>

#include "../common/test.h"

static struct sockaddr_in6 loopback_addr(void)
{
	struct sockaddr_in6 address = { 0 };
	address.sin6_family = AF_INET6;
	address.sin6_addr.s6_addr[15] = 1;
	return address;
}

FN_TEST(ipv6_tcp_socket_is_not_supported)
{
	/* IPv6 TCP 仍不属于当前 Raw Socket 阶段。 */
	TEST_ERRNO(socket(AF_INET6, SOCK_STREAM, 0), EAFNOSUPPORT);
}
END_TEST()

FN_TEST(ipv6_udp_socket_is_not_supported)
{
	/* IPv6 UDP 仍不属于当前 Raw Socket 阶段。 */
	TEST_ERRNO(socket(AF_INET6, SOCK_DGRAM, 0), EAFNOSUPPORT);
}
END_TEST()

FN_TEST(ipv6_raw_loopback_echo_and_options)
{
	const unsigned char request[] = {
		128, 0, 0, 0, 0x04, 0x23, 0, 7, 's', 't', 'a', 'g', 'e', '1', '0',
		'-', 'v', '6',
	};
	unsigned char packet[512] = { 0 };
	unsigned char send_control[CMSG_SPACE(sizeof(int)) * 2] = { 0 };
	unsigned char control[CMSG_SPACE(sizeof(int)) * 2] = { 0 };
	struct sockaddr_in6 destination = loopback_addr();
	struct sockaddr_in6 source = { 0 };
	struct iovec send_iov = {
		.iov_base = (void *)request,
		.iov_len = sizeof(request),
	};
	struct iovec iov = {
		.iov_base = packet,
		.iov_len = sizeof(packet),
	};
	struct msghdr send_message = {
		.msg_name = &destination,
		.msg_namelen = sizeof(destination),
		.msg_iov = &send_iov,
		.msg_iovlen = 1,
		.msg_control = send_control,
		.msg_controllen = sizeof(send_control),
	};
	struct msghdr message = {
		.msg_name = &source,
		.msg_namelen = sizeof(source),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	int hops = 37;
	int tclass = 0x2e;
	int receive_hops = 1;
	int receive_tclass = 1;
	int send_hops = 41;
	int send_tclass = 0x3a;
	int observed_hops = 0;
	int observed_tclass = 0;
	socklen_t option_len = sizeof(observed_hops);

	int raw_fd =
		TEST_SUCC(socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMPV6));
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops,
			     sizeof(hops)));
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IPV6, IPV6_TCLASS, &tclass,
			     sizeof(tclass)));
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
			     &receive_hops, sizeof(receive_hops)));
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IPV6, IPV6_RECVTCLASS,
			     &receive_tclass, sizeof(receive_tclass)));
	TEST_SUCC(getsockopt(raw_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			     &observed_hops, &option_len));
	TEST_RES(observed_hops, _ret == hops);
	option_len = sizeof(observed_tclass);
	TEST_SUCC(getsockopt(raw_fd, IPPROTO_IPV6, IPV6_TCLASS,
		     &observed_tclass, &option_len));
	TEST_RES(observed_tclass, _ret == tclass);

	TEST_SUCC(bind(raw_fd, (const struct sockaddr *)&destination,
		       sizeof(destination)));
	TEST_SUCC(connect(raw_fd, (const struct sockaddr *)&destination,
			  sizeof(destination)));
	struct cmsghdr *send_cmsg = CMSG_FIRSTHDR(&send_message);
	send_cmsg->cmsg_level = IPPROTO_IPV6;
	send_cmsg->cmsg_type = IPV6_HOPLIMIT;
	send_cmsg->cmsg_len = CMSG_LEN(sizeof(send_hops));
	memcpy(CMSG_DATA(send_cmsg), &send_hops, sizeof(send_hops));
	send_cmsg = CMSG_NXTHDR(&send_message, send_cmsg);
	send_cmsg->cmsg_level = IPPROTO_IPV6;
	send_cmsg->cmsg_type = IPV6_TCLASS;
	send_cmsg->cmsg_len = CMSG_LEN(sizeof(send_tclass));
	memcpy(CMSG_DATA(send_cmsg), &send_tclass, sizeof(send_tclass));
	TEST_RES(sendmsg(raw_fd, &send_message, 0),
		 _ret == (ssize_t)sizeof(request));

	ssize_t packet_len = TEST_SUCC(recvmsg(raw_fd, &message, 0));
	TEST_RES(packet_len, _ret >= 48);
	TEST_RES(source.sin6_family, _ret == AF_INET6);
	TEST_RES(source.sin6_addr.s6_addr[15], _ret == 1);
	if (packet_len >= 48) {
		TEST_RES(packet[0] >> 4, _ret == 6);
		TEST_RES(packet[6], _ret == IPPROTO_ICMPV6);
		TEST_RES(packet[7], _ret == send_hops);
		TEST_RES(packet[0] & 0x0f, _ret == send_tclass >> 4);
		TEST_RES(packet[1] >> 4, _ret == (send_tclass & 0x0f));
		TEST_RES(packet[40], _ret == 129);
		TEST_RES(packet[44], _ret == request[4]);
		TEST_RES(packet[45], _ret == request[5]);
		TEST_RES(packet[46], _ret == request[6]);
		TEST_RES(packet[47], _ret == request[7]);
	}
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&message, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6 ||
		    cmsg->cmsg_len < CMSG_LEN(sizeof(int)))
			continue;
		int value = *(int *)CMSG_DATA(cmsg);
		if (cmsg->cmsg_type == IPV6_HOPLIMIT)
			observed_hops = value;
		if (cmsg->cmsg_type == IPV6_TCLASS)
			observed_tclass = value;
	}
	TEST_RES(observed_hops, _ret == send_hops);
	TEST_RES(observed_tclass, _ret == send_tclass);
	TEST_SUCC(close(raw_fd));
}
END_TEST()

FN_TEST(ipv6_raw_hdrincl_custom_protocol)
{
	const unsigned char payload[] = "stage10-v6-hdrincl";
	unsigned char packet[40 + sizeof(payload)] = { 0 };
	unsigned char received[128] = { 0 };
	struct sockaddr_in6 destination = loopback_addr();
	struct sockaddr_in6 source = { 0 };
	socklen_t source_len = sizeof(source);
	struct pollfd poll_fd = { 0 };
	int hdrincl = 1;

	packet[0] = 0x62; /* IPv6 版本加非零流量类别。 */
	packet[4] = 0;
	packet[5] = sizeof(payload);
	packet[6] = 143;
	packet[7] = 19;
	packet[23] = 1;
	packet[39] = 1;
	memcpy(packet + 40, payload, sizeof(payload));

	int raw_fd = TEST_SUCC(socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK, 143));
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IPV6, IPV6_HDRINCL, &hdrincl,
			     sizeof(hdrincl)));
	TEST_RES(sendto(raw_fd, packet, sizeof(packet), 0,
			(const struct sockaddr *)&destination, sizeof(destination)),
		 _ret == (ssize_t)sizeof(packet));
	poll_fd.fd = raw_fd;
	poll_fd.events = POLLIN;
	TEST_RES(poll(&poll_fd, 1, 1000),
		 _ret == 1 && (poll_fd.revents & POLLIN));
	ssize_t received_len = TEST_SUCC(recvfrom(
		raw_fd, received, sizeof(received), 0,
		(struct sockaddr *)&source, &source_len));
	TEST_RES(received_len, _ret == (ssize_t)sizeof(packet));
	if (received_len == (ssize_t)sizeof(packet)) {
		TEST_RES(received[0] >> 4, _ret == 6);
		TEST_RES(received[6], _ret == 143);
		TEST_RES(received[7], _ret == 19);
		TEST_RES(memcmp(received + 40, payload, sizeof(payload)), _ret == 0);
	}
	TEST_RES(source.sin6_family, _ret == AF_INET6);
	TEST_SUCC(close(raw_fd));
}
END_TEST()

FN_TEST(ipv6_raw_local_error_queue)
{
	char payload = 0;
	unsigned char control[CMSG_SPACE(sizeof(struct sock_extended_err))] = { 0 };
	struct sockaddr_in6 destination = { 0 };
	destination.sin6_family = AF_INET6;
	destination.sin6_addr.s6_addr[0] = 0x20;
	destination.sin6_addr.s6_addr[1] = 0x01;
	destination.sin6_addr.s6_addr[2] = 0x0d;
	destination.sin6_addr.s6_addr[3] = 0xb8;
	struct iovec iov = {
		.iov_base = &payload,
		.iov_len = sizeof(payload),
	};
	struct msghdr message = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	int recverr = 1;

	int raw_fd = TEST_SUCC(socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK,
				     IPPROTO_UDP));
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IPV6, IPV6_RECVERR, &recverr,
			     sizeof(recverr)));
	TEST_ERRNO(sendto(raw_fd, &payload, sizeof(payload), 0,
			  (const struct sockaddr *)&destination, sizeof(destination)),
		   ENETUNREACH);
	struct pollfd error_poll = {
		.fd = raw_fd,
		.events = POLLERR,
	};
	TEST_RES(poll(&error_poll, 1, 0),
		 _ret == 1 && (error_poll.revents & POLLERR));
	TEST_RES(recvmsg(raw_fd, &message, MSG_ERRQUEUE), _ret == 0);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
	TEST_RES(cmsg != NULL, _ret == 1);
	if (cmsg != NULL && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err))) {
		struct sock_extended_err *extended =
			(struct sock_extended_err *)CMSG_DATA(cmsg);
		TEST_RES(cmsg->cmsg_level, _ret == IPPROTO_IPV6);
		TEST_RES(cmsg->cmsg_type, _ret == IPV6_RECVERR);
		TEST_RES(extended->ee_errno, _ret == ENETUNREACH);
		TEST_RES(extended->ee_origin, _ret == SO_EE_ORIGIN_LOCAL);
	}
	TEST_ERRNO(recvmsg(raw_fd, &message, MSG_ERRQUEUE), EAGAIN);
	TEST_SUCC(close(raw_fd));
}
END_TEST()
