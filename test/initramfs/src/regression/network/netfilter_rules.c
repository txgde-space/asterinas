// SPDX-License-Identifier: MPL-2.0

#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../common/test.h"

#define NETFILTER_RULES_PATH "/proc/netfilter_rules"

static ssize_t read_netfilter_rules_snapshot(char *buffer, size_t buffer_size)
{
	ssize_t bytes_read;
	int fd;

	fd = open(NETFILTER_RULES_PATH, O_RDONLY);
	if (fd < 0)
		return -1;

	bytes_read = read(fd, buffer, buffer_size - 1);
	if (bytes_read >= 0)
		buffer[bytes_read] = '\0';

	close(fd);
	return bytes_read;
}

static int run_iptables_command(char *const argv[])
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		execv(argv[0], argv);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) != pid)
		return -1;

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);

	return -1;
}

static int read_rule_counters_by_match(const char *buffer, const char *needle,
				       unsigned long long *packets,
				       unsigned long long *bytes)
{
	const char *match;
	const char *line;

	match = strstr(buffer, needle);
	if (match == NULL)
		return -1;

	line = match;
	while (line > buffer && *(line - 1) != '\n')
		line--;

	return sscanf(line, " rule %*u pkts %llu bytes %llu", packets, bytes) ==
		       2 ?
	       0 :
	       -1;
}

static int read_rule_counters(const char *buffer, uint16_t ident,
			      unsigned long long *packets,
			      unsigned long long *bytes)
{
	char needle[32];

	snprintf(needle, sizeof(needle), "icmp-echo-ident 0x%04x", ident);
	return read_rule_counters_by_match(buffer, needle, packets, bytes);
}

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

static int send_echo_and_wait_reply(uint16_t ident, uint16_t sequence)
{
	unsigned char request[sizeof(struct icmphdr) + 24] = { 0 };
	unsigned char packet[512];
	const char payload[] = "stage15-rule-counters";
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in source;
	socklen_t source_len = sizeof(source);
	struct pollfd poll_fd;
	int raw_fd;
	int found_reply = 0;

	struct icmphdr *request_header = (struct icmphdr *)request;
	request_header->type = ICMP_ECHO;
	request_header->code = 0;
	request_header->un.echo.id = htons(ident);
	request_header->un.echo.sequence = htons(sequence);
	memcpy(request + sizeof(*request_header), payload, sizeof(payload));
	request_header->checksum = internet_checksum(request, sizeof(request));

	raw_fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
	if (raw_fd < 0)
		return -1;

	if (sendto(raw_fd, request, sizeof(request), 0,
		   (const struct sockaddr *)&destination,
		   sizeof(destination)) != sizeof(request))
		goto out;

	poll_fd.fd = raw_fd;
	poll_fd.events = POLLIN;
	poll_fd.revents = 0;
	if (poll(&poll_fd, 1, 1000) != 1)
		goto out;

	for (int attempt = 0; attempt < 4 && !found_reply; attempt++) {
		ssize_t packet_len;
		struct iphdr *ip_header;
		size_t ip_header_len;
		struct icmphdr *icmp_header;

		source_len = sizeof(source);
		packet_len = recvfrom(raw_fd, packet, sizeof(packet), 0,
				      (struct sockaddr *)&source, &source_len);
		if (packet_len < (ssize_t)sizeof(struct iphdr))
			continue;

		ip_header = (struct iphdr *)packet;
		ip_header_len = ip_header->ihl * 4;
		if (ip_header_len < sizeof(*ip_header) ||
		    ip_header_len > (size_t)packet_len - sizeof(*icmp_header))
			continue;

		icmp_header = (struct icmphdr *)(packet + ip_header_len);
		if (ip_header->protocol == IPPROTO_ICMP &&
		    icmp_header->type == ICMP_ECHOREPLY &&
		    icmp_header->code == 0 &&
		    ntohs(icmp_header->un.echo.id) == ident &&
		    ntohs(icmp_header->un.echo.sequence) == sequence) {
			found_reply = 1;
		}
	}

out:
	close(raw_fd);
	errno = 0;
	return found_reply;
}

static int send_udp_and_wait_port_unreachable(uint16_t destination_port)
{
	unsigned char packet[512];
	const char payload[] = "stage20-udp-port-match";
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(destination_port),
	};
	struct pollfd poll_fd;
	int raw_fd;
	int udp_fd;
	int found_unreachable = 0;

	raw_fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
	if (raw_fd < 0)
		return -1;

	udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_fd < 0)
		goto out_raw;

	if (sendto(udp_fd, payload, sizeof(payload), 0,
		   (const struct sockaddr *)&destination,
		   sizeof(destination)) != sizeof(payload))
		goto out_udp;

	poll_fd.fd = raw_fd;
	poll_fd.events = POLLIN;
	poll_fd.revents = 0;
	if (poll(&poll_fd, 1, 500) != 1)
		goto out_udp;

	for (int attempt = 0; attempt < 4 && !found_unreachable; attempt++) {
		ssize_t packet_len;
		struct iphdr *ip_header;
		size_t ip_header_len;
		struct icmphdr *icmp_header;

		packet_len = recv(raw_fd, packet, sizeof(packet), 0);
		if (packet_len < (ssize_t)sizeof(struct iphdr))
			continue;

		ip_header = (struct iphdr *)packet;
		ip_header_len = ip_header->ihl * 4;
		if (ip_header_len < sizeof(*ip_header) ||
		    ip_header_len > (size_t)packet_len - sizeof(*icmp_header))
			continue;

		icmp_header = (struct icmphdr *)(packet + ip_header_len);
		if (ip_header->protocol == IPPROTO_ICMP &&
		    icmp_header->type == ICMP_DEST_UNREACH &&
		    icmp_header->code == ICMP_PORT_UNREACH) {
			found_unreachable = 1;
		}
	}

out_udp:
	close(udp_fd);
out_raw:
	close(raw_fd);
	errno = 0;
	return found_unreachable;
}

static int send_raw_icmp_datagram(uint32_t destination_addr, uint16_t ident)
{
	unsigned char request[sizeof(struct icmphdr) + 24] = { 0 };
	const char payload[] = "stage22-nat-egress";
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(destination_addr),
	};
	struct icmphdr *request_header = (struct icmphdr *)request;
	int raw_fd;
	int result;

	request_header->type = ICMP_ECHO;
	request_header->code = 0;
	request_header->un.echo.id = htons(ident);
	request_header->un.echo.sequence = htons(1);
	memcpy(request + sizeof(*request_header), payload, sizeof(payload));
	request_header->checksum = internet_checksum(request, sizeof(request));

	raw_fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
	if (raw_fd < 0)
		return -1;

	result = sendto(raw_fd, request, sizeof(request), 0,
			(const struct sockaddr *)&destination,
			sizeof(destination)) == sizeof(request) ?
			 0 :
			 -1;
	close(raw_fd);
	return result;
}

static int tcp_connect_refused_observed(uint16_t destination_port)
{
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(destination_port),
	};
	struct pollfd poll_fd;
	socklen_t error_len;
	int socket_error = 0;
	int socket_fd;
	int flags;
	int ret;

	socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socket_fd < 0)
		return -1;

	flags = fcntl(socket_fd, F_GETFL, 0);
	if (flags < 0 ||
	    fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) < 0)
		goto out;

	ret = connect(socket_fd, (const struct sockaddr *)&destination,
		      sizeof(destination));
	if (ret == 0)
		goto out;
	if (errno == ECONNREFUSED) {
		close(socket_fd);
		errno = 0;
		return 1;
	}
	if (errno != EINPROGRESS)
		goto out;

	poll_fd.fd = socket_fd;
	poll_fd.events = POLLOUT;
	poll_fd.revents = 0;
	ret = poll(&poll_fd, 1, 500);
	if (ret != 1)
		goto out;

	error_len = sizeof(socket_error);
	if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error,
		       &error_len) < 0)
		goto out;

	close(socket_fd);
	errno = 0;
	return socket_error == ECONNREFUSED;

out:
	close(socket_fd);
	errno = 0;
	return 0;
}

FN_TEST(read_netfilter_rules_snapshot)
{
	char buffer[512];
	unsigned long long bytes;
	unsigned long long packets;
	ssize_t bytes_read;
	int fd;

	fd = TEST_SUCC(open(NETFILTER_RULES_PATH, O_RDONLY));
	bytes_read = TEST_SUCC(read(fd, buffer, sizeof(buffer) - 1));
	buffer[bytes_read] = '\0';

	// NETFILTER_STAGE11: The first userspace control-plane smoke test is
	// intentionally read-only. It verifies that the kernel exposes the current
	// static filter chain/rule model without requiring an iptables ABI yet.
	TEST_RES(strstr(buffer, "table filter") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "chain OUTPUT policy ACCEPT") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0828") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "target DROP") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 1") != NULL,
		 _ret == 1);
	TEST_RES(read_rule_counters(buffer, 0x828, &packets, &bytes), _ret == 0);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(mutate_netfilter_output_rule_list)
{
	char buffer[512];
	const char flush_command[] = "flush OUTPUT";
	const char append_default_command[] =
		"append OUTPUT icmp-echo-ident 0x0828 DROP";
	const char append_second_command[] =
		"append OUTPUT icmp-echo-ident 0x0829 DROP";
	const char delete_first_command[] = "delete OUTPUT 0";
	ssize_t bytes_read;
	int fd;

	fd = TEST_SUCC(open(NETFILTER_RULES_PATH, O_RDWR));

	// NETFILTER_STAGE14: This covers a real ordered rule-list lifecycle:
	// append a second rule, delete the first rule by index, flush the chain,
	// and restore the default rule for later tests.
	TEST_RES(write(fd, append_second_command, sizeof(append_second_command) - 1),
		 _ret == sizeof(append_second_command) - 1);

	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	bytes_read = TEST_SUCC(read(fd, buffer, sizeof(buffer) - 1));
	buffer[bytes_read] = '\0';
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0828") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0829") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 2") != NULL,
		 _ret == 1);

	TEST_RES(send_echo_and_wait_reply(0x829, 0x14), _ret == 0);

	TEST_RES(write(fd, delete_first_command, sizeof(delete_first_command) - 1),
		 _ret == sizeof(delete_first_command) - 1);

	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	bytes_read = TEST_SUCC(read(fd, buffer, sizeof(buffer) - 1));
	buffer[bytes_read] = '\0';
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0828") == NULL, _ret == 1);
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0829") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 1") != NULL,
		 _ret == 1);

	TEST_RES(send_echo_and_wait_reply(0x828, 0x15), _ret == 1);
	TEST_RES(send_echo_and_wait_reply(0x829, 0x16), _ret == 0);

	TEST_RES(write(fd, flush_command, sizeof(flush_command) - 1),
		 _ret == sizeof(flush_command) - 1);

	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	bytes_read = TEST_SUCC(read(fd, buffer, sizeof(buffer) - 1));
	buffer[bytes_read] = '\0';
	TEST_RES(strstr(buffer, "target DROP") == NULL, _ret == 1);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 0") != NULL,
		 _ret == 1);

	TEST_RES(send_echo_and_wait_reply(0x829, 0x17), _ret == 1);

	TEST_RES(write(fd, append_default_command, sizeof(append_default_command) - 1),
		 _ret == sizeof(append_default_command) - 1);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(count_netfilter_rule_hits)
{
	char before[512];
	char after[512];
	unsigned long long before_bytes;
	unsigned long long before_packets;
	unsigned long long after_bytes;
	unsigned long long after_packets;

	// NETFILTER_STAGE15: A rule counter is only useful if it reflects the
	// packet path. Send two packets that match the default DROP rule and check
	// that both packet and byte counters increase.
	TEST_RES(read_netfilter_rules_snapshot(before, sizeof(before)), _ret > 0);
	TEST_RES(read_rule_counters(before, 0x828, &before_packets, &before_bytes),
		 _ret == 0);

	TEST_RES(send_echo_and_wait_reply(0x828, 0x18), _ret == 0);
	TEST_RES(send_echo_and_wait_reply(0x828, 0x19), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(after, sizeof(after)), _ret > 0);
	TEST_RES(read_rule_counters(after, 0x828, &after_packets, &after_bytes),
		 _ret == 0);

	TEST_RES(after_packets == before_packets + 2, _ret == 1);
	TEST_RES(after_bytes > before_bytes, _ret == 1);
}
END_TEST()

FN_TEST(zero_netfilter_rule_counters)
{
	char after[512];
	char before[512];
	const char zero_command[] = "zero OUTPUT";
	unsigned long long bytes;
	unsigned long long packets;
	int fd;

	fd = TEST_SUCC(open(NETFILTER_RULES_PATH, O_RDWR));

	// NETFILTER_STAGE16: Counter reset should not delete rules. It gives
	// userspace the same practical workflow as clearing iptables counters
	// before a focused packet-path experiment.
	TEST_RES(send_echo_and_wait_reply(0x828, 0x1a), _ret == 0);
	TEST_RES(read_netfilter_rules_snapshot(before, sizeof(before)), _ret > 0);
	TEST_RES(read_rule_counters(before, 0x828, &packets, &bytes), _ret == 0);
	TEST_RES(packets > 0, _ret == 1);
	TEST_RES(bytes > 0, _ret == 1);

	TEST_RES(write(fd, zero_command, sizeof(zero_command) - 1),
		 _ret == sizeof(zero_command) - 1);

	TEST_RES(read_netfilter_rules_snapshot(after, sizeof(after)), _ret > 0);
	TEST_RES(read_rule_counters(after, 0x828, &packets, &bytes), _ret == 0);
	TEST_RES(packets == 0, _ret == 1);
	TEST_RES(bytes == 0, _ret == 1);
	TEST_RES(strstr(after, "icmp-echo-ident 0x0828") != NULL, _ret == 1);

	TEST_SUCC(close(fd));
}
END_TEST()
