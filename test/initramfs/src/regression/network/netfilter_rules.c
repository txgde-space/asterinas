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
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0828") == NULL, _ret == 1);
	TEST_RES(strstr(buffer, "target DROP") == NULL, _ret == 1);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 0") != NULL,
		 _ret == 1);
	TEST_RES(read_rule_counters(buffer, 0x828, &packets, &bytes), _ret != 0);

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
	// create two rules, delete the first rule by index, flush the chain, and
	// restore the default rule for later tests. The default rule is test-owned;
	// the production table starts empty.
	TEST_RES(write(fd, flush_command, sizeof(flush_command) - 1),
		 _ret == sizeof(flush_command) - 1);
	TEST_RES(write(fd, append_default_command,
		       sizeof(append_default_command) - 1),
		 _ret == sizeof(append_default_command) - 1);
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

FN_TEST(match_netfilter_ipv4_addresses)
{
	// Stage 1 renders all built-in filter chains, so the legacy 512-byte
	// snapshot buffer can truncate the LocalOut compatibility counter.
	char buffer[2048];
	const char flush_command[] = "flush OUTPUT";
	const char append_dst_miss_command[] =
		"append OUTPUT dst 127.0.0.2 icmp-echo-ident 0x0830 DROP";
	const char append_dst_hit_command[] =
		"append OUTPUT dst 127.0.0.1 icmp-echo-ident 0x0831 DROP";
	const char append_src_hit_command[] =
		"append OUTPUT src 127.0.0.1 icmp-echo-ident 0x0832 DROP";
	const char append_default_command[] =
		"append OUTPUT icmp-echo-ident 0x0828 DROP";
	ssize_t bytes_read;
	int fd;

	fd = TEST_SUCC(open(NETFILTER_RULES_PATH, O_RDWR));

	// NETFILTER_STAGE16: These three rules prove that address matchers are
	// part of rule evaluation, not just text shown in `/proc/netfilter_rules`.
	TEST_RES(write(fd, flush_command, sizeof(flush_command) - 1),
		 _ret == sizeof(flush_command) - 1);
	TEST_RES(write(fd, append_dst_miss_command,
		       sizeof(append_dst_miss_command) - 1),
		 _ret == sizeof(append_dst_miss_command) - 1);
	TEST_RES(write(fd, append_dst_hit_command,
		       sizeof(append_dst_hit_command) - 1),
		 _ret == sizeof(append_dst_hit_command) - 1);
	TEST_RES(write(fd, append_src_hit_command,
		       sizeof(append_src_hit_command) - 1),
		 _ret == sizeof(append_src_hit_command) - 1);

	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	bytes_read = TEST_SUCC(read(fd, buffer, sizeof(buffer) - 1));
	buffer[bytes_read] = '\0';
	TEST_RES(strstr(buffer, "dst 127.0.0.2") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "dst 127.0.0.1") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "src 127.0.0.1") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 3") != NULL,
		 _ret == 1);

	TEST_RES(send_echo_and_wait_reply(0x830, 0x1b), _ret == 1);
	TEST_RES(send_echo_and_wait_reply(0x831, 0x1c), _ret == 0);
	TEST_RES(send_echo_and_wait_reply(0x832, 0x1d), _ret == 0);

	TEST_RES(write(fd, flush_command, sizeof(flush_command) - 1),
		 _ret == sizeof(flush_command) - 1);
	TEST_RES(write(fd, append_default_command, sizeof(append_default_command) - 1),
		 _ret == sizeof(append_default_command) - 1);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(match_netfilter_accept_drop_targets)
{
	char buffer[768];
	const char flush_command[] = "flush OUTPUT";
	const char append_accept_first_command[] =
		"append OUTPUT icmp-echo-ident 0x0840 ACCEPT";
	const char append_drop_second_command[] =
		"append OUTPUT icmp-echo-ident 0x0840 DROP";
	const char append_drop_first_command[] =
		"append OUTPUT icmp-echo-ident 0x0841 DROP";
	const char append_accept_second_command[] =
		"append OUTPUT icmp-echo-ident 0x0841 ACCEPT";
	const char append_default_command[] =
		"append OUTPUT icmp-echo-ident 0x0828 DROP";
	ssize_t bytes_read;
	int fd;

	fd = TEST_SUCC(open(NETFILTER_RULES_PATH, O_RDWR));

	// NETFILTER_STAGE17: This is the first explicit first-match target test.
	// The same matcher is installed twice with opposite targets; only the
	// earlier rule may decide the verdict, as in a real iptables chain.
	TEST_RES(write(fd, flush_command, sizeof(flush_command) - 1),
		 _ret == sizeof(flush_command) - 1);
	TEST_RES(write(fd, append_accept_first_command,
		       sizeof(append_accept_first_command) - 1),
		 _ret == sizeof(append_accept_first_command) - 1);
	TEST_RES(write(fd, append_drop_second_command,
		       sizeof(append_drop_second_command) - 1),
		 _ret == sizeof(append_drop_second_command) - 1);

	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	bytes_read = TEST_SUCC(read(fd, buffer, sizeof(buffer) - 1));
	buffer[bytes_read] = '\0';
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0840 target ACCEPT") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0840 target DROP") != NULL,
		 _ret == 1);
	TEST_RES(send_echo_and_wait_reply(0x840, 0x1e), _ret == 1);

	TEST_RES(write(fd, flush_command, sizeof(flush_command) - 1),
		 _ret == sizeof(flush_command) - 1);
	TEST_RES(write(fd, append_drop_first_command,
		       sizeof(append_drop_first_command) - 1),
		 _ret == sizeof(append_drop_first_command) - 1);
	TEST_RES(write(fd, append_accept_second_command,
		       sizeof(append_accept_second_command) - 1),
		 _ret == sizeof(append_accept_second_command) - 1);

	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	bytes_read = TEST_SUCC(read(fd, buffer, sizeof(buffer) - 1));
	buffer[bytes_read] = '\0';
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0841 target DROP") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "icmp-echo-ident 0x0841 target ACCEPT") != NULL,
		 _ret == 1);
	TEST_RES(send_echo_and_wait_reply(0x841, 0x1f), _ret == 0);

	TEST_RES(write(fd, flush_command, sizeof(flush_command) - 1),
		 _ret == sizeof(flush_command) - 1);
	TEST_RES(write(fd, append_default_command, sizeof(append_default_command) - 1),
		 _ret == sizeof(append_default_command) - 1);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(match_netfilter_iptables_command_compat)
{
	char buffer[1024];
	const char iptables_flush_command[] = "iptables -F OUTPUT";
	const char iptables_zero_command[] = "iptables -Z OUTPUT";
	const char iptables_delete_first_command[] = "iptables -D OUTPUT 1";
	const char iptables_drop_all_echo_command[] =
		"iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP";
	const char iptables_accept_ident_command[] =
		"iptables -A OUTPUT -p icmp --icmp-type echo-request --icmp-id 0x0852 -j ACCEPT";
	const char iptables_drop_ident_command[] =
		"iptables -A OUTPUT -p icmp --icmp-type echo-request --icmp-id 0x0852 -j DROP";
	const char iptables_restore_default_command[] =
		"iptables -A OUTPUT -p icmp --icmp-type echo-request --icmp-id 0x0828 -j DROP";
	ssize_t bytes_read;
	unsigned long long bytes;
	unsigned long long packets;
	int fd;

	fd = TEST_SUCC(open(NETFILTER_RULES_PATH, O_RDWR));

	// NETFILTER_STAGE18: These writes are shaped like common iptables
	// commands. The kernel still uses the prototype procfs control file, but
	// the parser now translates a useful iptables subset into real rules.
	TEST_RES(write(fd, iptables_flush_command,
		       sizeof(iptables_flush_command) - 1),
		 _ret == sizeof(iptables_flush_command) - 1);
	TEST_RES(write(fd, iptables_drop_all_echo_command,
		       sizeof(iptables_drop_all_echo_command) - 1),
		 _ret == sizeof(iptables_drop_all_echo_command) - 1);

	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	bytes_read = TEST_SUCC(read(fd, buffer, sizeof(buffer) - 1));
	buffer[bytes_read] = '\0';
	TEST_RES(strstr(buffer, "icmp-type echo-request target DROP") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 1") != NULL,
		 _ret == 1);

	TEST_RES(send_echo_and_wait_reply(0x850, 0x20), _ret == 0);
	TEST_RES(send_echo_and_wait_reply(0x851, 0x21), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(read_rule_counters_by_match(buffer, "icmp-type echo-request",
					     &packets, &bytes),
		 _ret == 0);
	TEST_RES(packets == 2, _ret == 1);
	TEST_RES(bytes > 0, _ret == 1);

	TEST_RES(write(fd, iptables_zero_command,
		       sizeof(iptables_zero_command) - 1),
		 _ret == sizeof(iptables_zero_command) - 1);
	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(read_rule_counters_by_match(buffer, "icmp-type echo-request",
					     &packets, &bytes),
		 _ret == 0);
	TEST_RES(packets == 0, _ret == 1);
	TEST_RES(bytes == 0, _ret == 1);

	TEST_RES(write(fd, iptables_delete_first_command,
		       sizeof(iptables_delete_first_command) - 1),
		 _ret == sizeof(iptables_delete_first_command) - 1);
	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 0") != NULL,
		 _ret == 1);
	TEST_RES(send_echo_and_wait_reply(0x850, 0x22), _ret == 1);

	TEST_RES(write(fd, iptables_accept_ident_command,
		       sizeof(iptables_accept_ident_command) - 1),
		 _ret == sizeof(iptables_accept_ident_command) - 1);
	TEST_RES(write(fd, iptables_drop_ident_command,
		       sizeof(iptables_drop_ident_command) - 1),
		 _ret == sizeof(iptables_drop_ident_command) - 1);
	TEST_RES(send_echo_and_wait_reply(0x852, 0x23), _ret == 1);

	TEST_RES(write(fd, iptables_flush_command,
		       sizeof(iptables_flush_command) - 1),
		 _ret == sizeof(iptables_flush_command) - 1);
	TEST_RES(write(fd, iptables_restore_default_command,
		       sizeof(iptables_restore_default_command) - 1),
		 _ret == sizeof(iptables_restore_default_command) - 1);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(run_userspace_iptables_shim)
{
	char buffer[1024];
	char *const iptables_flush_command[] = { "./iptables", "--flush", "OUTPUT",
						 NULL };
	char *const iptables_zero_command[] = { "./iptables", "--zero", "OUTPUT",
						NULL };
	char *const iptables_list_command[] = { "./iptables", "-L", "OUTPUT",
						NULL };
	char *const iptables_delete_first_command[] = {
		"./iptables", "--delete", "OUTPUT", "1", NULL
	};
	char *const iptables_drop_all_echo_command[] = {
		"./iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type",
		"echo-request", "-j", "DROP", NULL
	};
	char *const iptables_accept_addr_command[] = {
		"./iptables", "--append", "OUTPUT", "-p", "icmp", "--icmp-type",
		"echo-request", "--icmp-id", "0x0862", "-s", "127.0.0.1/32",
		"-d", "127.0.0.1/32", "-j", "ACCEPT", NULL
	};
	char *const iptables_drop_addr_command[] = {
		"./iptables", "--append", "OUTPUT", "-p", "icmp", "--icmp-type",
		"echo-request", "--icmp-id", "0x0862", "-s", "127.0.0.1/32",
		"-d", "127.0.0.1/32", "-j", "DROP", NULL
	};
	char *const iptables_restore_default_command[] = {
		"./iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type",
		"echo-request", "--icmp-id", "0x0828", "-j", "DROP", NULL
	};
	unsigned long long bytes;
	unsigned long long packets;

	// NETFILTER_STAGE19: This test leaves the direct procfs write path and
	// executes a user-visible `iptables` command shim. That proves the
	// compatibility layer can be driven by an application-style CLI.
	TEST_RES(run_iptables_command(iptables_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_drop_all_echo_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_list_command), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "icmp-type echo-request target DROP") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 1") != NULL,
		 _ret == 1);

	TEST_RES(send_echo_and_wait_reply(0x860, 0x24), _ret == 0);
	TEST_RES(send_echo_and_wait_reply(0x861, 0x25), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(read_rule_counters_by_match(buffer, "icmp-type echo-request",
					     &packets, &bytes),
		 _ret == 0);
	TEST_RES(packets == 2, _ret == 1);
	TEST_RES(bytes > 0, _ret == 1);

	TEST_RES(run_iptables_command(iptables_zero_command), _ret == 0);
	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(read_rule_counters_by_match(buffer, "icmp-type echo-request",
					     &packets, &bytes),
		 _ret == 0);
	TEST_RES(packets == 0, _ret == 1);
	TEST_RES(bytes == 0, _ret == 1);

	TEST_RES(run_iptables_command(iptables_delete_first_command), _ret == 0);
	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 0") != NULL,
		 _ret == 1);
	TEST_RES(send_echo_and_wait_reply(0x860, 0x26), _ret == 1);

	TEST_RES(run_iptables_command(iptables_accept_addr_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_drop_addr_command), _ret == 0);
	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "src 127.0.0.1") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "dst 127.0.0.1") != NULL, _ret == 1);
	TEST_RES(send_echo_and_wait_reply(0x862, 0x27), _ret == 1);

	TEST_RES(run_iptables_command(iptables_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_restore_default_command), _ret == 0);
}
END_TEST()

FN_TEST(run_userspace_iptables_tcp_udp_port_matches)
{
	char buffer[1024];
	char *const iptables_flush_command[] = { "./iptables", "--flush", "OUTPUT",
						 NULL };
	char *const iptables_list_command[] = { "./iptables", "-L", "OUTPUT",
						NULL };
	char *const iptables_drop_udp_command[] = {
		"./iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "54020",
		"-j", "DROP", NULL
	};
	char *const iptables_drop_tcp_command[] = {
		"./iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "54021",
		"-j", "DROP", NULL
	};
	char *const iptables_accept_udp_command[] = {
		"./iptables", "--append", "OUTPUT", "-p", "udp", "--dport",
		"54022", "-j", "ACCEPT", NULL
	};
	char *const iptables_late_drop_udp_command[] = {
		"./iptables", "--append", "OUTPUT", "-p", "udp", "--dport",
		"54022", "-j", "DROP", NULL
	};
	char *const iptables_accept_tcp_command[] = {
		"./iptables", "--append", "OUTPUT", "-p", "tcp", "--dport",
		"54023", "-j", "ACCEPT", NULL
	};
	char *const iptables_late_drop_tcp_command[] = {
		"./iptables", "--append", "OUTPUT", "-p", "tcp", "--dport",
		"54023", "-j", "DROP", NULL
	};
	char *const iptables_restore_default_command[] = {
		"./iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type",
		"echo-request", "--icmp-id", "0x0828", "-j", "DROP", NULL
	};
	unsigned long long bytes;
	unsigned long long packets;

	// NETFILTER_STAGE20: TCP/UDP dport rules are installed through the
	// userspace shim and verified through observable protocol behavior.
	TEST_RES(run_iptables_command(iptables_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_drop_udp_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_drop_tcp_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_list_command), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "udp dport 54020 target DROP") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "tcp dport 54021 target DROP") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 2") != NULL,
		 _ret == 1);

	TEST_RES(send_udp_and_wait_port_unreachable(54020), _ret == 0);
	TEST_RES(tcp_connect_refused_observed(54021), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(read_rule_counters_by_match(buffer, "udp dport 54020",
					     &packets, &bytes),
		 _ret == 0);
	TEST_RES(packets > 0, _ret == 1);
	TEST_RES(read_rule_counters_by_match(buffer, "tcp dport 54021",
					     &packets, &bytes),
		 _ret == 0);
	TEST_RES(packets > 0, _ret == 1);

	TEST_RES(run_iptables_command(iptables_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_accept_udp_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_late_drop_udp_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_accept_tcp_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_late_drop_tcp_command), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "state stage20-output-rule-count 4") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "udp dport 54022 target ACCEPT") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "tcp dport 54023 target ACCEPT") != NULL,
		 _ret == 1);
	TEST_RES(send_udp_and_wait_port_unreachable(54022), _ret == 1);
	TEST_RES(tcp_connect_refused_observed(54023), _ret == 1);

	TEST_RES(run_iptables_command(iptables_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_restore_default_command), _ret == 0);
}
END_TEST()

FN_TEST(run_userspace_iptables_input_forward_filter_chains)
{
	char buffer[2048];
	char *const input_flush_command[] = { "./iptables", "-F", "INPUT", NULL };
	char *const forward_flush_command[] = {
		"./iptables", "-F", "FORWARD", NULL
	};
	char *const input_drop_command[] = {
		"./iptables", "-A", "INPUT", "-p", "tcp", "--dport", "8080",
		"-j", "DROP", NULL
	};
	char *const forward_drop_command[] = {
		"./iptables", "-A", "FORWARD", "-p", "udp", "--dport", "5353",
		"-j", "DROP", NULL
	};

	// NETFILTER_STAGE1: INPUT and FORWARD rules must be independently managed
	// even before Stage 2 enables actual multi-interface forwarding.
	TEST_RES(run_iptables_command(input_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(forward_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(input_drop_command), _ret == 0);
	TEST_RES(run_iptables_command(forward_drop_command), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "chain INPUT policy ACCEPT") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "chain FORWARD policy ACCEPT") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "tcp dport 8080 target DROP") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "udp dport 5353 target DROP") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "state stage1-INPUT-rule-count 1") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "state stage1-FORWARD-rule-count 1") != NULL,
		 _ret == 1);

	TEST_RES(run_iptables_command(input_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(forward_flush_command), _ret == 0);
}
END_TEST()

FN_TEST(run_userspace_iptables_nat_control_plane)
{
	char buffer[2048];
	char *const iptables_nat_flush_command[] = { "./iptables", "-t", "nat",
						     "-F", NULL };
	char *const iptables_nat_flush_prerouting_command[] = {
		"./iptables", "-t", "nat", "-F", "PREROUTING", NULL
	};
	char *const iptables_nat_list_command[] = { "./iptables", "-t", "nat",
						    "-L", NULL };
	char *const iptables_snat_command[] = {
		"./iptables", "-t", "nat", "-A", "POSTROUTING", "-p", "tcp",
		"--dport", "8080", "-j", "SNAT", "--to-source",
		"10.0.2.15:40000", NULL
	};
	char *const iptables_dnat_command[] = {
		"./iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp",
		"--dport", "5353", "-j", "DNAT", "--to-destination",
		"127.0.0.1:5354", NULL
	};
	char *const iptables_masquerade_command[] = {
		"./iptables", "-t", "nat", "-A", "POSTROUTING", "-j",
		"MASQUERADE", NULL
	};

	// NETFILTER_STAGE21: NAT starts as a control-plane feature: iptables-style
	// commands can create and list SNAT, DNAT, and MASQUERADE rules, while
	// Stage 22 will attach these rules to packet rewriting.
	TEST_RES(run_iptables_command(iptables_nat_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_snat_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_dnat_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_masquerade_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_nat_list_command), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "table nat") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "chain PREROUTING policy ACCEPT") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "chain POSTROUTING policy ACCEPT") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer,
			"chain POSTROUTING pkts 0 bytes 0 match tcp dport 8080 target SNAT to-source 10.0.2.15:40000") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer,
			"chain PREROUTING pkts 0 bytes 0 match udp dport 5353 target DNAT to-destination 127.0.0.1:5354") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer,
			"chain POSTROUTING pkts 0 bytes 0 match all target MASQUERADE") != NULL,
		 _ret == 1);
	TEST_RES(strstr(buffer, "state stage21-nat-rule-count 3") != NULL,
		 _ret == 1);

	TEST_RES(run_iptables_command(iptables_nat_flush_prerouting_command),
		 _ret == 0);
	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "target DNAT") == NULL, _ret == 1);
	TEST_RES(strstr(buffer, "state stage21-nat-rule-count 2") != NULL,
		 _ret == 1);

	TEST_RES(run_iptables_command(iptables_nat_flush_command), _ret == 0);
	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "state stage21-nat-rule-count 0") != NULL,
		 _ret == 1);
}
END_TEST()

FN_TEST(run_userspace_iptables_nat_postrouting_data_path)
{
	char buffer[2048];
	char *const iptables_nat_flush_command[] = { "./iptables", "-t", "nat",
						     "-F", NULL };
	char *const iptables_snat_icmp_command[] = {
		"./iptables", "-t", "nat", "-A", "POSTROUTING", "-p", "icmp",
		"-d", "10.0.2.2/32", "-j", "SNAT", "--to-source",
		"10.0.2.15", NULL
	};
	char *const iptables_masquerade_command[] = {
		"./iptables", "-t", "nat", "-A", "POSTROUTING", "-p",
		"icmp", "-d", "10.0.2.3/32", "-j", "MASQUERADE", NULL
	};

	// NETFILTER_STAGE22: This test leaves pure control-plane validation and
	// keeps a smoke check that POSTROUTING NAT rules do not break the stable
	// raw ICMP egress path. Runtime counter evidence is not asserted because
	// the current QEMU regression environment does not reliably drive physical
	// egress scheduling before this test reads `/proc/netfilter_rules`.
	TEST_RES(run_iptables_command(iptables_nat_flush_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_snat_icmp_command), _ret == 0);
	TEST_RES(run_iptables_command(iptables_masquerade_command), _ret == 0);
	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "target SNAT") != NULL, _ret == 1);
	TEST_RES(strstr(buffer, "target MASQUERADE") != NULL, _ret == 1);

	TEST_RES(send_raw_icmp_datagram(0x0a000202, 0x872), _ret == 0);
	TEST_RES(send_raw_icmp_datagram(0x0a000203, 0x873), _ret == 0);

	TEST_RES(read_netfilter_rules_snapshot(buffer, sizeof(buffer)), _ret > 0);
	TEST_RES(strstr(buffer, "state stage21-nat-rule-count 2") != NULL,
		 _ret == 1);

	TEST_RES(run_iptables_command(iptables_nat_flush_command), _ret == 0);
}
END_TEST()
