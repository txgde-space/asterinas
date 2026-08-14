// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/test.h"

FN_TEST(create_icmp_raw_socket)
{
	// RAW_SOCKET_STAGE1: This guards the ABI and CAP_NET_RAW creation path.
	int socket_fd = TEST_SUCC(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
	TEST_SUCC(close(socket_fd));
}
END_TEST()

FN_TEST(create_multi_protocol_raw_sockets)
{
	// RAW_SOCKET_P0：创建 Socket 时协议号不再仅限 ICMP。TCP、UDP 和实验协议
	// 都使用相同的 IPv4 Raw Socket ABI，并且必须保留各自的协议选择器。
	const int protocols[] = { IPPROTO_TCP, IPPROTO_UDP, 143 };
	for (size_t i = 0; i < sizeof(protocols) / sizeof(protocols[0]); i++) {
		int socket_fd =
			TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, protocols[i]));
		TEST_SUCC(close(socket_fd));
	}
}
END_TEST()

FN_TEST(send_loopback_raw_udp_payload)
{
	const unsigned char payload[] = "stage-p0-raw-udp";
	unsigned char packet[512];
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in source;
	socklen_t source_len = sizeof(source);
	struct pollfd poll_fd = { 0 };
	int ttl = 31;
	// 现有 IP_TOS ABI 会保留 ECN 低位；这里使用 ECN 为零的值，
	// 使线格式断言能够测试 DSCP/TOS 传播。
	int tos = 0x2c;

	int raw_fd =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP));
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)));
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
	TEST_RES(sendto(raw_fd, payload, sizeof(payload), 0,
			(const struct sockaddr *)&destination,
			sizeof(destination)),
		 _ret == (ssize_t)sizeof(payload));

	poll_fd.fd = raw_fd;
	poll_fd.events = POLLIN;
	TEST_RES(poll(&poll_fd, 1, 1000),
		 _ret == 1 && (poll_fd.revents & POLLIN));

	ssize_t packet_len =
		TEST_SUCC(recvfrom(raw_fd, packet, sizeof(packet), 0,
				   (struct sockaddr *)&source, &source_len));
	TEST_RES(packet_len, _ret >= (ssize_t)sizeof(struct iphdr) +
					   (ssize_t)sizeof(payload));
	if (packet_len >= (ssize_t)sizeof(struct iphdr) + (ssize_t)sizeof(payload)) {
		struct iphdr *ip_header = (struct iphdr *)packet;
		size_t ip_header_len = ip_header->ihl * 4;
		TEST_RES(ip_header->protocol, _ret == IPPROTO_UDP);
		TEST_RES(ip_header->ttl, _ret == ttl);
		TEST_RES(ip_header->tos, _ret == tos);
		TEST_RES(memcmp(packet + ip_header_len, payload, sizeof(payload)),
			 _ret == 0);
	}
	TEST_RES(source.sin_family, _ret == AF_INET);
	TEST_RES(source.sin_addr.s_addr, _ret == htonl(INADDR_LOOPBACK));
	TEST_SUCC(close(raw_fd));
}
END_TEST()

FN_TEST(sendmsg_raw_udp_ancillary_options)
{
	const unsigned char payload[] = "stage9d-raw-ancillary";
	unsigned char packet[512];
	unsigned char control[CMSG_SPACE(sizeof(int)) * 2] = { 0 };
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in source;
	socklen_t source_len = sizeof(source);
	struct pollfd poll_fd = { 0 };
	struct iovec iov = {
		.iov_base = (void *)payload,
		.iov_len = sizeof(payload),
	};
	struct msghdr message = {
		.msg_name = &destination,
		.msg_namelen = sizeof(destination),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	const int ancillary_ttl = 43;
	const int ancillary_tos = 0x2c;

	struct cmsghdr *cmsg = (struct cmsghdr *)control;
	cmsg->cmsg_len = CMSG_LEN(sizeof(ancillary_ttl));
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_TTL;
	memcpy(CMSG_DATA(cmsg), &ancillary_ttl, sizeof(ancillary_ttl));

	cmsg = (struct cmsghdr *)(control + CMSG_SPACE(sizeof(ancillary_ttl)));
	cmsg->cmsg_len = CMSG_LEN(sizeof(ancillary_tos));
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_TOS;
	memcpy(CMSG_DATA(cmsg), &ancillary_tos, sizeof(ancillary_tos));

	int raw_sender =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP));
	int raw_receiver =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP));

	// RAW_SOCKET_STAGE9D：sendmsg 辅助数据仅覆盖一个 IPv4 Raw 数据包的
	// Socket 级默认值，不改变后续发送。
	TEST_RES(sendmsg(raw_sender, &message, 0),
		 _ret == (ssize_t)sizeof(payload));

	poll_fd.fd = raw_receiver;
	poll_fd.events = POLLIN;
	TEST_RES(poll(&poll_fd, 1, 1000),
		 _ret == 1 && (poll_fd.revents & POLLIN));

	ssize_t packet_len =
		TEST_SUCC(recvfrom(raw_receiver, packet, sizeof(packet), 0,
				   (struct sockaddr *)&source, &source_len));
	TEST_RES(packet_len, _ret >= (ssize_t)sizeof(struct iphdr) +
					   (ssize_t)sizeof(payload));
	if (packet_len >= (ssize_t)sizeof(struct iphdr) + (ssize_t)sizeof(payload)) {
		struct iphdr *ip_header = (struct iphdr *)packet;
		size_t ip_header_len = ip_header->ihl * 4;
		TEST_RES(ip_header->protocol, _ret == IPPROTO_UDP);
		TEST_RES(ip_header->ttl, _ret == ancillary_ttl);
		TEST_RES(ip_header->tos, _ret == ancillary_tos);
		TEST_RES(memcmp(packet + ip_header_len, payload, sizeof(payload)),
			 _ret == 0);
	}
	TEST_RES(source.sin_family, _ret == AF_INET);
	TEST_SUCC(close(raw_receiver));
	TEST_SUCC(close(raw_sender));
}
END_TEST()

FN_TEST(raw_ip_recverr_local_error_queue)
{
	char payload[1] = { 0 };
	unsigned char control[CMSG_SPACE(sizeof(struct sock_extended_err))] = { 0 };
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	struct iovec iov = {
		.iov_base = payload,
		.iov_len = sizeof(payload),
	};
	struct msghdr message = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	int recverr = 1;
	int raw_fd =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP));

	// RAW_SOCKET_STAGE9E：IP_RECVERR 保留本地路由失败，公开 POLLERR，
	// 并通过 MSG_ERRQUEUE 返回固定的 sock_extended_err 控制消息。
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IP, IP_RECVERR, &recverr,
			     sizeof(recverr)));
	TEST_ERRNO(sendto(raw_fd, payload, sizeof(payload), 0,
			  (const struct sockaddr *)&destination,
			  sizeof(destination)), ENETUNREACH);
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
		TEST_RES(cmsg->cmsg_level, _ret == IPPROTO_IP);
		TEST_RES(cmsg->cmsg_type, _ret == IP_RECVERR);
		TEST_RES(extended->ee_errno, _ret == ENETUNREACH);
		TEST_RES(extended->ee_origin, _ret == SO_EE_ORIGIN_LOCAL);
	}
	TEST_ERRNO(recvmsg(raw_fd, &message, MSG_ERRQUEUE), EAGAIN);
	TEST_SUCC(close(raw_fd));
}
END_TEST()

FN_TEST(receive_local_port_unreachable)
{
	char payload[] = "stage2-icmp-ingress";
	unsigned char packet[512];
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_port = htons(65534),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in source;
	socklen_t source_len = sizeof(source);
	struct pollfd poll_fd;

	int raw_fd =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP));
	int udp_fd = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));

	TEST_RES(sendto(udp_fd, payload, sizeof(payload), 0,
			(const struct sockaddr *)&destination,
			sizeof(destination)),
		 _ret == sizeof(payload));

	poll_fd.fd = raw_fd;
	poll_fd.events = POLLIN;
	poll_fd.revents = 0;
	TEST_RES(poll(&poll_fd, 1, 1000),
		 _ret == 1 && (poll_fd.revents & POLLIN));

	ssize_t packet_len =
		TEST_SUCC(recvfrom(raw_fd, packet, sizeof(packet), 0,
				   (struct sockaddr *)&source, &source_len));
	TEST_RES(packet_len, _ret >= (ssize_t)sizeof(struct iphdr));
	if (packet_len < (ssize_t)sizeof(struct iphdr))
		goto out;

	struct iphdr *ip_header = (struct iphdr *)packet;
	size_t ip_header_len = ip_header->ihl * 4;
	TEST_RES(ip_header_len,
		 _ret >= sizeof(*ip_header) &&
			 _ret <= (size_t)packet_len - sizeof(struct icmphdr));
	if (ip_header_len < sizeof(*ip_header) ||
	    ip_header_len > (size_t)packet_len - sizeof(struct icmphdr))
		goto out;

	struct icmphdr *icmp_header =
		(struct icmphdr *)(packet + ip_header_len);

	// RAW_SOCKET_STAGE2: Validate the full local ingress-to-userspace path.
	TEST_RES(ip_header->protocol, _ret == IPPROTO_ICMP);
	TEST_RES(icmp_header->type, _ret == ICMP_DEST_UNREACH);
	TEST_RES(icmp_header->code, _ret == ICMP_PORT_UNREACH);
	TEST_RES(source.sin_family, _ret == AF_INET);
	TEST_RES(source.sin_addr.s_addr,
		 _ret == htonl(INADDR_LOOPBACK));

out:
	TEST_SUCC(close(udp_fd));
	TEST_SUCC(close(raw_fd));
}
END_TEST()

static uint16_t internet_checksum(const void *data, size_t len)
{
	const uint16_t *words = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *words++;
		len -= 2;
	}

	if (len != 0) {
		uint16_t tail = 0;
		memcpy(&tail, words, 1);
		sum += tail;
	}

	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

FN_TEST(send_loopback_echo_request)
{
	unsigned char request[sizeof(struct icmphdr) + 18] = { 0 };
	unsigned char packet[512];
	const char payload[] = "stage3-raw-echo";
	const uint16_t ident = 0x423;
	const uint16_t sequence = 0x7;
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in source;
	socklen_t source_len = sizeof(source);
	struct pollfd poll_fd;
	int found_reply = 0;

	struct icmphdr *request_header = (struct icmphdr *)request;
	request_header->type = ICMP_ECHO;
	request_header->code = 0;
	request_header->un.echo.id = htons(ident);
	request_header->un.echo.sequence = htons(sequence);
	memcpy(request + sizeof(*request_header), payload, sizeof(payload));
	request_header->checksum = internet_checksum(request, sizeof(request));

	int raw_fd =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP));

	// RAW_SOCKET_STAGE3: This validates the raw ICMP egress path and the
	// minimal local Echo Request to Echo Reply path used by loopback ping.
	TEST_RES(sendto(raw_fd, request, sizeof(request), 0,
			(const struct sockaddr *)&destination,
			sizeof(destination)),
		 _ret == sizeof(request));

	poll_fd.fd = raw_fd;
	poll_fd.events = POLLIN;
	poll_fd.revents = 0;
	TEST_RES(poll(&poll_fd, 1, 1000),
		 _ret == 1 && (poll_fd.revents & POLLIN));

	for (int attempt = 0; attempt < 4 && !found_reply; attempt++) {
		source_len = sizeof(source);
		ssize_t packet_len =
			TEST_SUCC(recvfrom(raw_fd, packet, sizeof(packet), 0,
					   (struct sockaddr *)&source,
					   &source_len));
		TEST_RES(packet_len, _ret >= (ssize_t)sizeof(struct iphdr));
		if (packet_len < (ssize_t)sizeof(struct iphdr))
			continue;

		struct iphdr *ip_header = (struct iphdr *)packet;
		size_t ip_header_len = ip_header->ihl * 4;
		if (ip_header_len < sizeof(*ip_header) ||
		    ip_header_len > (size_t)packet_len - sizeof(struct icmphdr))
			continue;

		struct icmphdr *icmp_header =
			(struct icmphdr *)(packet + ip_header_len);
		if (ip_header->protocol == IPPROTO_ICMP &&
		    icmp_header->type == ICMP_ECHOREPLY &&
		    icmp_header->code == 0 &&
		    ntohs(icmp_header->un.echo.id) == ident &&
		    ntohs(icmp_header->un.echo.sequence) == sequence) {
			found_reply = 1;
		}
	}

	TEST_RES(found_reply, _ret == 1);
	TEST_RES(source.sin_family, _ret == AF_INET);
	TEST_RES(source.sin_addr.s_addr, _ret == htonl(INADDR_LOOPBACK));
	TEST_SUCC(close(raw_fd));
}
END_TEST()

FN_TEST(send_hdrincl_loopback_echo_request)
{
	unsigned char received[512];
	const char payload[] = "stage4-hdrincl-echo";
	unsigned char packet[sizeof(struct iphdr) + sizeof(struct icmphdr) +
			     sizeof(payload)] = { 0 };
	const uint16_t ident = 0x424;
	const uint16_t sequence = 0x8;
	int hdrincl = 1;
	socklen_t hdrincl_len = sizeof(hdrincl);
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in source;
	socklen_t source_len = sizeof(source);
	struct pollfd poll_fd;
	int found_reply = 0;

	struct iphdr *ip_header = (struct iphdr *)packet;
	struct icmphdr *request_header =
		(struct icmphdr *)(packet + sizeof(*ip_header));

	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->tot_len = htons(sizeof(packet));
	ip_header->ttl = 64;
	ip_header->protocol = IPPROTO_ICMP;
	ip_header->saddr = htonl(INADDR_LOOPBACK);
	ip_header->daddr = htonl(INADDR_LOOPBACK);
	ip_header->check = internet_checksum(ip_header, sizeof(*ip_header));

	request_header->type = ICMP_ECHO;
	request_header->code = 0;
	request_header->un.echo.id = htons(ident);
	request_header->un.echo.sequence = htons(sequence);
	memcpy(packet + sizeof(*ip_header) + sizeof(*request_header), payload,
	       sizeof(payload));
	request_header->checksum =
		internet_checksum(request_header, sizeof(*request_header) +
						   sizeof(payload));

	int raw_fd =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP));

	// RAW_SOCKET_STAGE4: `IP_HDRINCL` is a common raw IPv4 compatibility
	// option used by tools that construct their own IPv4 header.
	TEST_SUCC(setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &hdrincl,
			     sizeof(hdrincl)));
	hdrincl = 0;
	TEST_SUCC(getsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &hdrincl,
			     &hdrincl_len));
	TEST_RES(hdrincl, _ret == 1);

	TEST_RES(sendto(raw_fd, packet, sizeof(packet), 0,
			(const struct sockaddr *)&destination,
			sizeof(destination)),
		 _ret == sizeof(packet));

	poll_fd.fd = raw_fd;
	poll_fd.events = POLLIN;
	poll_fd.revents = 0;
	TEST_RES(poll(&poll_fd, 1, 1000),
		 _ret == 1 && (poll_fd.revents & POLLIN));

	for (int attempt = 0; attempt < 4 && !found_reply; attempt++) {
		source_len = sizeof(source);
		ssize_t packet_len =
			TEST_SUCC(recvfrom(raw_fd, received, sizeof(received), 0,
					   (struct sockaddr *)&source,
					   &source_len));
		if (packet_len < (ssize_t)sizeof(struct iphdr))
			continue;

		struct iphdr *reply_ip_header = (struct iphdr *)received;
		size_t ip_header_len = reply_ip_header->ihl * 4;
		if (ip_header_len < sizeof(*reply_ip_header) ||
		    ip_header_len >
			    (size_t)packet_len - sizeof(struct icmphdr))
			continue;

		struct icmphdr *reply_icmp_header =
			(struct icmphdr *)(received + ip_header_len);
		if (reply_ip_header->protocol == IPPROTO_ICMP &&
		    reply_icmp_header->type == ICMP_ECHOREPLY &&
		    reply_icmp_header->code == 0 &&
		    ntohs(reply_icmp_header->un.echo.id) == ident &&
		    ntohs(reply_icmp_header->un.echo.sequence) == sequence) {
			found_reply = 1;
		}
	}

	TEST_RES(found_reply, _ret == 1);
	TEST_RES(source.sin_family, _ret == AF_INET);
	TEST_RES(source.sin_addr.s_addr, _ret == htonl(INADDR_LOOPBACK));
	TEST_SUCC(close(raw_fd));
}
END_TEST()

FN_TEST(send_ipproto_raw_hdrincl_preserves_options)
{
	unsigned char packet[sizeof(struct iphdr) + 24] = { 0 };
	unsigned char received[512];
	const char payload[] = "stage-p1-hdrincl-udp";
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in source;
	socklen_t source_len = sizeof(source);
	struct pollfd poll_fd = { 0 };
	int hdrincl = 1;

	struct iphdr *ip_header = (struct iphdr *)packet;
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->tos = 0x2e;
	ip_header->tot_len = htons(sizeof(packet));
	ip_header->ttl = 37;
	ip_header->protocol = IPPROTO_UDP;
	ip_header->saddr = htonl(INADDR_LOOPBACK);
	ip_header->daddr = htonl(INADDR_LOOPBACK);
	memcpy(packet + sizeof(*ip_header), payload, sizeof(payload));
	ip_header->check = internet_checksum(ip_header, sizeof(*ip_header));

	// IPPROTO_RAW 仅用于发送，并从 IP_HDRINCL 中选择协议。
	int raw_sender = TEST_SUCC(
		socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW));
	int raw_receiver =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP));
	TEST_SUCC(setsockopt(raw_sender, IPPROTO_IP, IP_HDRINCL, &hdrincl,
			     sizeof(hdrincl)));

	TEST_RES(sendto(raw_sender, packet, sizeof(packet), 0,
			(const struct sockaddr *)&destination,
			sizeof(destination)),
		 _ret == (ssize_t)sizeof(packet));

	poll_fd.fd = raw_receiver;
	poll_fd.events = POLLIN;
	TEST_RES(poll(&poll_fd, 1, 1000),
		 _ret == 1 && (poll_fd.revents & POLLIN));

	ssize_t packet_len =
		TEST_SUCC(recvfrom(raw_receiver, received, sizeof(received), 0,
				   (struct sockaddr *)&source, &source_len));
	TEST_RES(packet_len, _ret == (ssize_t)sizeof(packet));
	if (packet_len == (ssize_t)sizeof(packet)) {
		struct iphdr *received_header = (struct iphdr *)received;
		size_t ip_header_len = received_header->ihl * 4;
		TEST_RES(received_header->protocol, _ret == IPPROTO_UDP);
		TEST_RES(received_header->tos, _ret == 0x2e);
		TEST_RES(received_header->ttl, _ret == 37);
		TEST_RES(received_header->saddr,
			 _ret == htonl(INADDR_LOOPBACK));
		TEST_RES(received_header->daddr,
			 _ret == htonl(INADDR_LOOPBACK));
		TEST_RES(memcmp(received + ip_header_len, payload, sizeof(payload)),
			 _ret == 0);
	}
	TEST_RES(source.sin_family, _ret == AF_INET);
	TEST_SUCC(close(raw_receiver));
	TEST_SUCC(close(raw_sender));
}
END_TEST()

FN_TEST(netfilter_static_drop_icmp_echo)
{
	unsigned char request[sizeof(struct icmphdr) + 20] = { 0 };
	const char payload[] = "stage8-static-drop";
	const uint16_t ident = 0x828;
	const uint16_t sequence = 0x9;
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct pollfd poll_fd;
	const char flush_command[] = "iptables -F OUTPUT";
	const char drop_command[] =
		"iptables -A OUTPUT -p icmp --icmp-type echo-request "
		"--icmp-id 0x0828 -j DROP";
	int rules_fd = TEST_SUCC(open("/proc/netfilter_rules", O_RDWR));
	TEST_RES(write(rules_fd, flush_command, sizeof(flush_command) - 1),
		 _ret == sizeof(flush_command) - 1);
	TEST_RES(write(rules_fd, drop_command, sizeof(drop_command) - 1),
		 _ret == sizeof(drop_command) - 1);

	struct icmphdr *request_header = (struct icmphdr *)request;
	request_header->type = ICMP_ECHO;
	request_header->code = 0;
	request_header->un.echo.id = htons(ident);
	request_header->un.echo.sequence = htons(sequence);
	memcpy(request + sizeof(*request_header), payload, sizeof(payload));
	request_header->checksum = internet_checksum(request, sizeof(request));

	int raw_fd =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP));

	// NETFILTER_STAGE8: The kernel has a static LOCAL_OUT filter rule that
	// drops this test-only ICMP Echo identifier. `sendto` still succeeds
	// because the packet is accepted by the socket layer, but no Echo Reply
	// should be delivered back to the raw socket.
	TEST_RES(sendto(raw_fd, request, sizeof(request), 0,
			(const struct sockaddr *)&destination,
			sizeof(destination)),
		 _ret == sizeof(request));

	poll_fd.fd = raw_fd;
	poll_fd.events = POLLIN;
	poll_fd.revents = 0;
	TEST_RES(poll(&poll_fd, 1, 300), _ret == 0);

	TEST_RES(write(rules_fd, flush_command, sizeof(flush_command) - 1),
		 _ret == sizeof(flush_command) - 1);
	TEST_SUCC(close(rules_fd));
	TEST_SUCC(close(raw_fd));
}
END_TEST()

FN_TEST(nonblocking_empty_receive)
{
	// RAW_SOCKET_STAGE2: An empty nonblocking receive must expose queue state.
	char buffer[64];
	int socket_fd =
		TEST_SUCC(socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP));

	TEST_ERRNO(recv(socket_fd, buffer, sizeof(buffer), 0), EAGAIN);
	TEST_SUCC(close(socket_fd));
}
END_TEST()
