// SPDX-License-Identifier: MPL-2.0

/* 阶段 8 Netfilter 演示的交互式展示流程。 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define RULES_PATH "/proc/netfilter_rules"
#define CONTROL_COMMAND_SIZE 384
#define CONTROL_ARG_MAX 16

struct demo_step {
	const char *id;
	const char *scenario;
	const char *title;
};

static const struct demo_step STEPS[] = {
	{ "filter-baseline", "filter", "清空 OUTPUT，查看基线" },
	{ "filter-drop-rule", "filter", "追加 ICMP DROP 规则" },
	{ "filter-drop-packet", "filter", "发送 ICMP，观察 DROP 和计数器" },
	{ "filter-check-rule", "filter", "执行 iptables -C 检查规则" },
	{ "filter-replace-accept", "filter", "用 iptables -R 替换为 ACCEPT" },
	{ "conntrack-policy", "conntrack", "建立 FORWARD NEW/ESTABLISHED 策略" },
	{ "nat-policy", "nat", "建立 DNAT 与 MASQUERADE 规则" },
	{ "cleanup", "cleanup", "清理演示规则并恢复默认策略" },
};

static int run_program(char *const argv[])
{
	int status;
	pid_t pid = fork();

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

static int run_action(const char *name, char *const argv[])
{
	int rc = run_program(argv);

	fprintf(stderr, "NETFILTER_DEMO action=%s rc=%d\n", name, rc);
	fflush(stderr);
	return rc;
}

static void emit_snapshot(const char *label)
{
	char buffer[16384];
	FILE *file = fopen(RULES_PATH, "r");
	size_t bytes;

	fprintf(stderr, "NETFILTER_DEMO snapshot-begin label=%s\n", label);
	if (file != NULL) {
		while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0)
			fwrite(buffer, 1, bytes, stderr);
		fclose(file);
	}
	fprintf(stderr, "NETFILTER_DEMO snapshot-end label=%s\n", label);
	fflush(stderr);
}

static void emit_flow(const char *name, const char *protocol,
			      const char *original, const char *translated,
			      const char *state, const char *verdict)
{
	fprintf(stderr,
		"NETFILTER_DEMO flow=%s protocol=%s original=%s translated=%s "
		"state=%s verdict=%s\n",
		name, protocol, original, translated, state, verdict);
	fflush(stderr);
}

static void emit_step(const struct demo_step *step, const char *status)
{
	fprintf(stderr,
		"NETFILTER_DEMO step=%s scenario=%s title=\"%s\" status=%s\n",
		step->id, step->scenario, step->title, status);
	fflush(stderr);
}

static int run_iptables(const char *name, char *const argv[])
{
	return run_action(name, argv);
}

static int write_netfilter_command(const char *command)
{
	const size_t command_len = strlen(command);
	int fd = open(RULES_PATH, O_WRONLY);
	ssize_t written;

	if (fd < 0)
		return errno;
	written = write(fd, command, command_len);
	close(fd);
	return written == (ssize_t)command_len ? 0 : (errno != 0 ? errno : EIO);
}

static int is_rule_command(const char *command, const char **family)
{
	if (strncmp(command, "iptables ", 9) == 0) {
		*family = "ipv4";
		return 1;
	}
	if (strncmp(command, "ip6tables ", 10) == 0) {
		*family = "ipv6";
		return 1;
	}
	return 0;
}

static int run_manual_rule_command(const char *command)
{
	static unsigned long sequence;
	const char *family;
	char copy[CONTROL_COMMAND_SIZE];
	char *saveptr = NULL;
	char *program;
	char *operation;
	char label[48];
	int rc;

	if (strlen(command) >= sizeof(copy) || !is_rule_command(command, &family))
		return EINVAL;
	strcpy(copy, command);
	program = strtok_r(copy, " \t", &saveptr);
	operation = strtok_r(NULL, " \t", &saveptr);
	if (program == NULL || operation == NULL)
		return EINVAL;

	/* 列表为只读内容，使用与 dashboard 相同的快照呈现。
	 * 所有修改操作都经过真实的 procfs iptables/ip6tables 解析器。 */
	if (strcmp(operation, "-L") == 0 || strcmp(operation, "--list") == 0)
		rc = 0;
	else
		rc = write_netfilter_command(command);

	sequence++;
	snprintf(label, sizeof(label), "manual-%lu", sequence);
	fprintf(stderr, "NETFILTER_DEMO control=rule family=%s rc=%d id=%lu\n",
		family, rc, sequence);
	fflush(stderr);
	if (rc == 0)
		emit_snapshot(label);
	return rc;
}

static int parse_probe_number(const char *text, int minimum, int maximum,
				      int *value)
{
	char *end = NULL;
	long parsed;

	errno = 0;
	parsed = strtol(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || parsed < minimum ||
	    parsed > maximum)
		return EINVAL;
	*value = (int)parsed;
	return 0;
}

static int run_probe_command(const char *command)
{
	char copy[CONTROL_COMMAND_SIZE];
	char *argv[CONTROL_ARG_MAX];
	char *saveptr = NULL;
	char *token;
	char count_text[16];
	char timeout_text[16];
	const char *family;
	const char *target;
	int count;
	int timeout;
	int argc = 0;
	int rc;

	if (strlen(command) >= sizeof(copy))
		return EINVAL;
	strcpy(copy, command);
	while ((token = strtok_r(argc == 0 ? copy : NULL, " \t", &saveptr)) != NULL) {
		if (argc == CONTROL_ARG_MAX - 1)
			return E2BIG;
		argv[argc++] = token;
	}
	if (argc != 4 || strcmp(argv[0], "ping4") != 0)
		return EINVAL;
	family = "ipv4";
	target = argv[1];
	if (strlen(target) == 0 || strlen(target) > 64 ||
	    strpbrk(target, "\r\n \t\"'"))
		return EINVAL;
	if (parse_probe_number(argv[2], 1, 5, &count) != 0 ||
	    parse_probe_number(argv[3], 1, 5, &timeout) != 0)
		return EINVAL;

	snprintf(count_text, sizeof(count_text), "%d", count);
	snprintf(timeout_text, sizeof(timeout_text), "%d", timeout);
	{
		char *probe_argv[] = {
			"/bin/ping", "-4",
			"-n", "-c", count_text, "-W", timeout_text, (char *)target,
			NULL,
		};
		rc = run_program(probe_argv);
	}
	fprintf(stderr,
		"NETFILTER_DEMO probe=ping family=%s target=%s count=%d timeout=%d rc=%d\n",
		family, target, count, timeout, rc);
	fflush(stderr);
	return rc;
}

static int reset_rules(void)
{
	char *const filter_flush[] = { "./iptables", "-F", "OUTPUT", NULL };
	char *const forward_flush[] = { "./iptables", "-F", "FORWARD", NULL };
	char *const nat_flush[] = { "./iptables", "-t", "nat", "-F", NULL };
	char *const filter_policy[] = { "./iptables", "-P", "OUTPUT", "ACCEPT", NULL };
	char *const forward_policy[] = { "./iptables", "-P", "FORWARD", "ACCEPT", NULL };
	char *const filter6_flush[] = { "./ip6tables", "-F", "OUTPUT", NULL };
	char *const forward6_flush[] = { "./ip6tables", "-F", "FORWARD", NULL };
	char *const nat6_flush[] = { "./ip6tables", "-t", "nat", "-F", NULL };
	char *const filter6_policy[] = { "./ip6tables", "-P", "OUTPUT", "ACCEPT", NULL };
	char *const forward6_policy[] = { "./ip6tables", "-P", "FORWARD", "ACCEPT", NULL };
	int rc = 0;

	rc |= run_iptables("reset-filter-flush", filter_flush) != 0;
	rc |= run_iptables("reset-forward-flush", forward_flush) != 0;
	rc |= run_iptables("reset-nat-flush", nat_flush) != 0;
	rc |= run_iptables("reset-filter-policy", filter_policy) != 0;
	rc |= run_iptables("reset-forward-policy", forward_policy) != 0;
	/* IPv6 规则会在同一次 dashboard 操作中重置，使 IPv6 规则表仍可检查，
	 * 即使当前演示只公开 IPv4 ping 探测。 */
	if (access("./ip6tables", X_OK) == 0) {
		rc |= run_iptables("reset-ipv6-filter-flush", filter6_flush) != 0;
		rc |= run_iptables("reset-ipv6-forward-flush", forward6_flush) != 0;
		rc |= run_iptables("reset-ipv6-nat-flush", nat6_flush) != 0;
		rc |= run_iptables("reset-ipv6-filter-policy", filter6_policy) != 0;
		rc |= run_iptables("reset-ipv6-forward-policy", forward6_policy) != 0;
	}
	fprintf(stderr, "NETFILTER_DEMO reset rc=%d\n", rc);
	fflush(stderr);
	return rc;
}

static int run_probe_suite(const char *suite)
{
	static const char *const local[] = { "ping4 10.0.3.2 2 2", NULL };
	static const char *const external[] = { "ping4 1.1.1.1 2 3", NULL };
	const char *const *probes;
	int rc = 0;

	if (strcmp(suite, "local") == 0)
		probes = local;
	else if (strcmp(suite, "external") == 0)
		probes = external;
	else
		return EINVAL;

	for (size_t i = 0; probes[i] != NULL; i++)
		rc |= run_probe_command(probes[i]) != 0;
	fprintf(stderr, "NETFILTER_DEMO probe-suite=%s rc=%d\n", suite, rc);
	fflush(stderr);
	return rc;
}

static int run_ping(const char *name, int expect_success)
{
	char *const ping[] = { "/bin/ping", "-c", "1", "-W", "1",
				       "127.0.0.1", NULL };
	int observed_rc = run_program(ping);
	int passed = (observed_rc == 0) == expect_success;
	const char *verdict = observed_rc == 0 ? "ACCEPT" : "DROP";

	fprintf(stderr,
		"NETFILTER_DEMO action=%s rc=%d observed_rc=%d expected=%s\n",
		name, passed ? 0 : 1, observed_rc,
		expect_success ? "ACCEPT" : "DROP");
	fflush(stderr);
	emit_flow("local-output", "ICMP", "127.0.0.1", "127.0.0.1", "NEW",
		   verdict);
	return passed ? 0 : 1;
}

static int run_filter_step(const char *id)
{
	char *const flush[] = { "./iptables", "-F", "OUTPUT", NULL };
	char *const append_drop[] = { "./iptables", "-A", "OUTPUT", "-p",
						      "icmp", "--icmp-type", "echo-request",
						      "-j", "DROP", NULL };
	char *const check_drop[] = { "./iptables", "-C", "OUTPUT", "-p",
						     "icmp", "--icmp-type", "echo-request",
						     "-j", "DROP", NULL };
	char *const replace_accept[] = { "./iptables", "-R", "OUTPUT", "1",
										"-p", "icmp", "--icmp-type", "echo-request",
										"-j", "ACCEPT", NULL };

	if (strcmp(id, "filter-baseline") == 0) {
		if (run_iptables("filter-flush", flush) != 0)
			return 1;
		emit_snapshot("step-filter-baseline");
		return 0;
	}
	if (strcmp(id, "filter-drop-rule") == 0) {
		if (run_iptables("filter-append-drop", append_drop) != 0)
			return 1;
		emit_snapshot("step-filter-drop-rule");
		return 0;
	}
	if (strcmp(id, "filter-drop-packet") == 0) {
		if (run_ping("filter-ping-drop", 0) != 0)
			return 1;
		emit_snapshot("step-filter-drop-packet");
		return 0;
	}
	if (strcmp(id, "filter-check-rule") == 0)
		return run_iptables("filter-check-drop", check_drop) == 0 ? 0 : 1;
	if (strcmp(id, "filter-replace-accept") == 0) {
		if (run_iptables("filter-replace-accept", replace_accept) != 0)
			return 1;
		if (run_ping("filter-ping-accept", 1) != 0)
			return 1;
		emit_snapshot("step-filter-replace-accept");
		return 0;
	}
	return 1;
}

static int run_conntrack_step(void)
{
	char *const flush[] = { "./iptables", "-F", "FORWARD", NULL };
	char *const policy[] = { "./iptables", "-P", "FORWARD", "DROP", NULL };
	char *const allow_new[] = { "./iptables", "-A", "FORWARD", "-p",
					    "tcp", "--dport", "9000", "-m", "conntrack",
					    "--ctstate", "NEW", "-j", "ACCEPT", NULL };
	char *const allow_established[] = {
		"./iptables", "-A", "FORWARD", "-p", "tcp", "-m", "conntrack",
		"--ctstate", "ESTABLISHED", "-j", "ACCEPT", NULL
	};

	if (run_iptables("conntrack-flush", flush) != 0 ||
	    run_iptables("conntrack-policy-drop", policy) != 0 ||
	    run_iptables("conntrack-allow-new", allow_new) != 0 ||
	    run_iptables("conntrack-allow-established", allow_established) != 0)
		return 1;
	emit_flow("forward-new", "TCP", "10.0.2.2:40000->10.0.3.2:9000",
		   "10.0.2.2:40000->10.0.3.2:9000", "NEW", "ACCEPT");
	emit_flow("forward-reply", "TCP", "10.0.3.2:9000->10.0.2.2:40000",
		   "10.0.3.2:9000->10.0.2.2:40000", "ESTABLISHED", "ACCEPT");
	emit_snapshot("step-conntrack-policy");
	return 0;
}

static int run_nat_step(void)
{
	char *const flush[] = { "./iptables", "-t", "nat", "-F", NULL };
	char *const dnat[] = { "./iptables", "-t", "nat", "-A", "PREROUTING",
				       "-p", "tcp", "--dport", "8080", "-j", "DNAT",
				       "--to-destination", "10.0.3.2:9000", NULL };
	char *const masquerade[] = { "./iptables", "-t", "nat", "-A",
					     "POSTROUTING", "-j", "MASQUERADE", NULL };

	if (run_iptables("nat-flush", flush) != 0 ||
	    run_iptables("nat-append-dnat", dnat) != 0 ||
	    run_iptables("nat-append-masquerade", masquerade) != 0)
		return 1;
	emit_flow("dnat", "TCP", "10.0.2.2:33001->10.0.2.15:8080",
		   "10.0.2.2:33001->10.0.3.2:9000", "NEW", "DNAT");
	emit_flow("masquerade", "TCP", "10.0.2.2:40000->10.0.3.2:9000",
		   "10.0.3.15:40000->10.0.3.2:9000", "NEW", "MASQUERADE");
	emit_snapshot("step-nat-policy");
	return 0;
}

static int run_step(size_t index)
{
	const char *id = STEPS[index].id;

	if (strcmp(STEPS[index].scenario, "filter") == 0)
		return run_filter_step(id);
	if (strcmp(id, "conntrack-policy") == 0)
		return run_conntrack_step();
	if (strcmp(id, "nat-policy") == 0)
		return run_nat_step();
	return reset_rules();
}

static int run_scenario(const char *scenario)
{
	size_t i;

	fprintf(stderr, "NETFILTER_DEMO scenario=%s phase=begin mode=automatic\n",
		scenario);
	for (i = 0; i < sizeof(STEPS) / sizeof(STEPS[0]); i++) {
		if (strcmp(scenario, "all") != 0 &&
		    strcmp(scenario, STEPS[i].scenario) != 0)
			continue;
		emit_step(&STEPS[i], "running");
		if (run_step(i) != 0) {
			emit_step(&STEPS[i], "fail");
			return 1;
		}
		emit_step(&STEPS[i], "done");
	}
	fprintf(stderr, "NETFILTER_DEMO scenario=%s phase=end mode=automatic\n",
		scenario);
	fflush(stderr);
	return 0;
}

static int read_command(char *buffer, size_t size)
{
	if (fgets(buffer, (int)size, stdin) == NULL)
		return -1;
	buffer[strcspn(buffer, "\r\n")] = '\0';
	return 0;
}

int main(void)
{
	size_t next = 0;
	char command[CONTROL_COMMAND_SIZE];
	int complete_emitted = 0;

	fprintf(stderr,
		"NETFILTER_DEMO topology left=10.0.2.2 router-left=10.0.2.15 "
		"router-right=10.0.3.15 right=10.0.3.2 mode=interactive\n");
	if (reset_rules() != 0)
		return 1;

	while (1) {
		const struct demo_step *step =
			next < sizeof(STEPS) / sizeof(STEPS[0]) ? &STEPS[next] : NULL;

		if (step != NULL) {
			emit_step(step, "waiting");
			fprintf(stderr, "NETFILTER_DEMO prompt=next step=%s\n", step->id);
		} else if (!complete_emitted) {
			if (reset_rules() != 0)
				return 1;
			fprintf(stderr, "NETFILTER_DEMO complete=1\n");
			fprintf(stderr,
				"NETFILTER_DEMO prompt=manual commands=rule,ping,snapshot,reset,quit\n");
			complete_emitted = 1;
		}
		fflush(stderr);
		if (read_command(command, sizeof(command)) != 0)
			return 1;
		if (step != NULL &&
		    (command[0] == '\0' || strcmp(command, "next") == 0 ||
		     strcmp(command, "n") == 0)) {
			emit_step(step, "running");
			if (run_step(next) != 0) {
				emit_step(step, "fail");
				return 1;
			}
			emit_step(step, "done");
			next++;
			continue;
		}
		if (strcmp(command, "reset") == 0 || strcmp(command, "r") == 0) {
			if (reset_rules() != 0)
				return 1;
			next = 0;
			complete_emitted = 0;
			fprintf(stderr, "NETFILTER_DEMO complete=0\n");
			fflush(stderr);
			continue;
		}
		if (strncmp(command, "scenario ", 9) == 0) {
			if (reset_rules() != 0 || run_scenario(command + 9) != 0)
				return 1;
			if (strcmp(command + 9, "all") == 0) {
				next = sizeof(STEPS) / sizeof(STEPS[0]);
			} else {
				size_t i;
				for (i = 0; i < sizeof(STEPS) / sizeof(STEPS[0]); i++) {
					if (strcmp(command + 9, STEPS[i].scenario) == 0)
						next = i + 1;
				}
			}
			continue;
		}
		if (strncmp(command, "iptables ", 9) == 0 ||
		    strncmp(command, "ip6tables ", 10) == 0) {
			if (run_manual_rule_command(command) != 0)
				fprintf(stderr,
					"NETFILTER_DEMO control-error=rule command=invalid\n");
			fflush(stderr);
			continue;
		}
		if (strncmp(command, "ping4 ", 6) == 0) {
			if (run_probe_command(command) != 0)
				fprintf(stderr,
					"NETFILTER_DEMO control-error=ping command=invalid\n");
			fflush(stderr);
			continue;
		}
		if (strncmp(command, "probe-suite ", 13) == 0) {
			if (run_probe_suite(command + 13) != 0)
				fprintf(stderr,
					"NETFILTER_DEMO control-error=probe-suite suite=%s\n",
					command + 13);
			fflush(stderr);
			continue;
		}
		if (strcmp(command, "snapshot") == 0) {
			emit_snapshot("manual-request");
			continue;
		}
		if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0)
			break;
		fprintf(stderr, "NETFILTER_DEMO error=unknown-command command=%s\n",
			command);
		fflush(stderr);
	}

	fprintf(stderr, "Interactive Netfilter demo finished.\n");
	return 0;
}
