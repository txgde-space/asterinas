// SPDX-License-Identifier: MPL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
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
