// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NETFILTER_RULES_PATH "/proc/netfilter_rules"
#define COMMAND_BUFFER_SIZE 320
#define SNAPSHOT_BUFFER_SIZE 2048

static int append_token(char *buffer, size_t buffer_size, const char *token)
{
	size_t used = strlen(buffer);
	int written;

	written = snprintf(buffer + used, buffer_size - used, " %s", token);
	if (written < 0 || (size_t)written >= buffer_size - used) {
		errno = ENOSPC;
		return -1;
	}

	return 0;
}

static const char *normalize_operation(const char *operation)
{
	if (strcmp(operation, "--append") == 0)
		return "-A";
	if (strcmp(operation, "--delete") == 0)
		return "-D";
	if (strcmp(operation, "--flush") == 0)
		return "-F";
	if (strcmp(operation, "--zero") == 0)
		return "-Z";
	if (strcmp(operation, "--list") == 0)
		return "-L";

	return operation;
}

static int command_requires_default_output_chain(const char *operation)
{
	return strcmp(operation, "-F") == 0 || strcmp(operation, "-Z") == 0 ||
	       strcmp(operation, "-L") == 0;
}

static int table_is_nat(const char *table)
{
	return table != NULL && strcmp(table, "nat") == 0;
}

static int list_rules(void)
{
	char buffer[SNAPSHOT_BUFFER_SIZE];
	ssize_t bytes_read;
	int fd;

	fd = open(NETFILTER_RULES_PATH, O_RDONLY);
	if (fd < 0) {
		perror("iptables: open");
		return 1;
	}

	bytes_read = read(fd, buffer, sizeof(buffer));
	close(fd);
	if (bytes_read < 0) {
		perror("iptables: read");
		return 1;
	}

	if (write(STDOUT_FILENO, buffer, bytes_read) != bytes_read) {
		perror("iptables: write stdout");
		return 1;
	}

	return 0;
}

static int write_command(const char *command)
{
	int fd;
	size_t command_len = strlen(command);

	fd = open(NETFILTER_RULES_PATH, O_WRONLY);
	if (fd < 0) {
		perror("iptables: open");
		return 1;
	}

	if (write(fd, command, command_len) != (ssize_t)command_len) {
		perror("iptables: write");
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}

