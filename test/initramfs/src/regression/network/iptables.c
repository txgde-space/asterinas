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
	if (strcmp(operation, "--insert") == 0)
		return "-I";
	if (strcmp(operation, "--delete") == 0)
		return "-D";
	if (strcmp(operation, "--flush") == 0)
		return "-F";
	if (strcmp(operation, "--zero") == 0)
		return "-Z";
	if (strcmp(operation, "--list") == 0)
		return "-L";
	if (strcmp(operation, "--policy") == 0)
		return "-P";

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

int main(int argc, char *argv[])
{
	char command[COMMAND_BUFFER_SIZE] = "iptables";
	const char *table = NULL;
	const char *operation;
	int operation_index = 1;
	int first_copied_arg;

	if (argc < 2) {
		fprintf(stderr, "usage: iptables [-t filter|nat] -A|-I|-D|-F|-P|-Z|-L CHAIN ...\n");
		return 2;
	}

	if (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--table") == 0) {
		if (argc < 4) {
			fprintf(stderr, "iptables: missing table operation\n");
			return 2;
		}
		table = argv[2];
		if (strcmp(table, "filter") != 0 && strcmp(table, "nat") != 0) {
			fprintf(stderr, "iptables: unsupported table %s\n", table);
			return 2;
		}
		if (append_token(command, sizeof(command), "-t") < 0 ||
		    append_token(command, sizeof(command), table) < 0)
			return 2;
		operation_index = 3;
	}

	operation = normalize_operation(argv[operation_index]);
	if (strcmp(operation, "-A") != 0 && strcmp(operation, "-I") != 0 &&
	    strcmp(operation, "-D") != 0 && strcmp(operation, "-F") != 0 &&
	    strcmp(operation, "-P") != 0 && strcmp(operation, "-Z") != 0 &&
	    strcmp(operation, "-L") != 0) {
		fprintf(stderr, "iptables: unsupported operation %s\n",
			argv[operation_index]);
		return 2;
	}
	if (table_is_nat(table) && (strcmp(operation, "-I") == 0 ||
			      strcmp(operation, "-P") == 0 ||
			      strcmp(operation, "-Z") == 0)) {
		fprintf(stderr, "iptables: operation unsupported for NAT table\n");
		return 2;
	}

	if (append_token(command, sizeof(command), operation) < 0)
		return 2;

	first_copied_arg = operation_index + 1;
	if (!table_is_nat(table) && argc == operation_index + 1 &&
	    command_requires_default_output_chain(operation)) {
		if (append_token(command, sizeof(command), "OUTPUT") < 0)
			return 2;
	} else if (!table_is_nat(table) && argc < operation_index + 2) {
		fprintf(stderr, "iptables: missing chain\n");
		return 2;
	}

	for (int arg_index = first_copied_arg; arg_index < argc; arg_index++) {
		if (append_token(command, sizeof(command), argv[arg_index]) < 0) {
			fprintf(stderr, "iptables: command too long\n");
			return 2;
		}
	}

	// NETFILTER_STAGE19: `-L/--list` is handled in userspace because it is a
	// read-only query. Mutating commands are forwarded to the kernel's Stage 18
	// iptables-compatible parser through `/proc/netfilter_rules`.
	if (strcmp(operation, "-L") == 0)
		return list_rules();

	return write_command(command);
}
