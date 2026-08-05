#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

"""Local, dependency-free control dashboard for the Asterinas netfilter demo.

The page is deliberately local-only by default.  It reads the guest's
NETFILTER_DEMO serial trace and sends a small, validated command language to
the demo-step guest over its UNIX serial socket.  The guest still performs
the actual iptables write, procfs snapshot, and ping operation.  Hostname
lookups are performed here on Ubuntu and only the resulting numeric IPv4
address is sent to the guest.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


DEMO_PREFIX = "NETFILTER_DEMO "
SNAPSHOT_BEGIN = re.compile(r"^NETFILTER_DEMO snapshot-begin label=(\S+)")
SNAPSHOT_END = re.compile(r"^NETFILTER_DEMO snapshot-end label=(\S+)")
TABLE_RE = re.compile(r"^table\s+(\S+)")
CHAIN_RE = re.compile(
    r"^chain(?P<v6>6)?(?P<nat>nat)?\s+(?P<chain>\S+)\s+policy\s+(?P<policy>\S+)"
)
RULE_RE = re.compile(
    r"^\s*rule(?P<v6>6)?(?P<nat>nat)?\s+(?P<number>\d+)\s+"
    r"pkts\s+(?P<packets>\d+)\s+bytes\s+(?P<bytes>\d+)\s+match\s+(?P<rest>.*)"
)
TOKEN_RE = re.compile(r"^[A-Za-z0-9_./:+,@%!=\-\[\]]+$")
OPERATIONS = {
    "-A", "--append", "-I", "--insert", "-D", "--delete", "-F", "--flush",
    "-P", "--policy", "-Z", "--zero", "-L", "--list",
    "-C", "--check", "-R", "--replace",
}
OPERATION_ALIASES = {
    "--append": "-A", "--insert": "-I", "--delete": "-D", "--flush": "-F",
    "--policy": "-P", "--zero": "-Z", "--list": "-L",
    "--check": "-C", "--replace": "-R",
}

# Targets on the isolated Stage 2 topology are deterministic and do not
# depend on the Ubuntu VM's uplink or DNS.  Internet targets are kept as
# explicit IPv4 presets; the dashboard intentionally does not issue IPv6 pings.
PROBE_PRESETS = [
    {"id": "v4-left", "family": "4", "label": "IPv4 左端点", "target": "10.0.2.2", "scope": "local"},
    {"id": "v4-right", "family": "4", "label": "IPv4 右端点", "target": "10.0.3.2", "scope": "local"},
    {"id": "v4-router-left", "family": "4", "label": "IPv4 路由器左侧", "target": "10.0.2.15", "scope": "local"},
    {"id": "v4-router-right", "family": "4", "label": "IPv4 路由器右侧", "target": "10.0.3.15", "scope": "local"},
    {"id": "v4-internet", "family": "4", "label": "IPv4 外网（需上行）", "target": "1.1.1.1", "scope": "external"},
]
LOCAL_PROBE_TARGETS = {item["target"] for item in PROBE_PRESETS if item["scope"] == "local"}
PROBE_SUITES = {
    "local": "IPv4 isolated-topology smoke",
    "external": "IPv4 external-uplink smoke",
}
HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# These are the fixed endpoint namespaces created by
# tools/net/stage2-router-topology.sh.  Keeping the endpoint and namespace
# names in a small allow-list means the dashboard can run real directional
# probes without becoming a general-purpose shell endpoint.
DIRECTION_TARGETS = {
    "left-to-right": {
        "label": "Left -> right",
        "namespace": "as2left",
        "source": "10.0.2.2",
        "target": "10.0.3.2",
    },
    "right-to-left": {
        "label": "Right -> left",
        "namespace": "as2right",
        "source": "10.0.3.2",
        "target": "10.0.2.2",
    },
}
EXPECTATION_PROFILES = {
    "observe": None,
    "both": {"left-to-right": True, "right-to-left": True},
    "left-only": {"left-to-right": True, "right-to-left": False},
    "right-only": {"left-to-right": False, "right-to-left": True},
    "deny-both": {"left-to-right": False, "right-to-left": False},
}

# Recipes intentionally use only the rule subset already accepted by the
# Guest procfs parser.  A recipe is still sent through the same validated
# rule channel as a manually typed command, so the UI demonstrates the real
# iptables lifecycle rather than maintaining a second fake model.
LAB_PROFILES = {
    "allow-both": {
        "label": "Allow both forwarding directions",
        "probe": "icmp",
        "actions": [
            ("reset", ""),
            ("iptables", "-P FORWARD ACCEPT"),
        ],
        "expected": {"left-to-right": True, "right-to-left": True},
    },
    "allow-left": {
        "label": "Allow only left -> right (NEW + ESTABLISHED)",
        "probe": "icmp",
        "actions": [
            ("reset", ""),
            ("iptables", "-P FORWARD DROP"),
            ("iptables", "-A FORWARD -s 10.0.2.2 -d 10.0.3.2 -p icmp -m conntrack --ctstate NEW -j ACCEPT"),
            ("iptables", "-A FORWARD -p icmp -m conntrack --ctstate ESTABLISHED -j ACCEPT"),
        ],
        "expected": {"left-to-right": True, "right-to-left": False},
    },
    "allow-right": {
        "label": "Allow only right -> left (NEW + ESTABLISHED)",
        "probe": "icmp",
        "actions": [
            ("reset", ""),
            ("iptables", "-P FORWARD DROP"),
            ("iptables", "-A FORWARD -s 10.0.3.2 -d 10.0.2.2 -p icmp -m conntrack --ctstate NEW -j ACCEPT"),
            ("iptables", "-A FORWARD -p icmp -m conntrack --ctstate ESTABLISHED -j ACCEPT"),
        ],
        "expected": {"left-to-right": False, "right-to-left": True},
    },
    "deny-both": {
        "label": "Drop both forwarding directions",
        "probe": "icmp",
        "actions": [
            ("reset", ""),
            ("iptables", "-P FORWARD DROP"),
        ],
        "expected": {"left-to-right": False, "right-to-left": False},
    },
    "conntrack": {
        "label": "TCP NEW/ESTABLISHED + port 9000",
        "probe": "rule-only",
        "actions": [
            ("reset", ""),
            ("iptables", "-P FORWARD DROP"),
            ("iptables", "-A FORWARD -p tcp --dport 9000 -m conntrack --ctstate NEW -j ACCEPT"),
            ("iptables", "-A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT"),
        ],
        "expected": {},
    },
    "masquerade": {
        "label": "POSTROUTING MASQUERADE",
        "probe": "rule-only",
        "actions": [
            ("reset", ""),
            ("iptables", "-t nat -A POSTROUTING -j MASQUERADE"),
        ],
        "expected": {},
    },
    "dnat": {
        "label": "PREROUTING DNAT 8080 -> 10.0.3.2:9000",
        "probe": "rule-only",
        "actions": [
            ("reset", ""),
            ("iptables", "-t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.0.3.2:9000"),
        ],
        "expected": {},
    },
    "check-replace": {
        "label": "-C check then -R replace",
        "probe": "rule-only",
        "actions": [
            ("reset", ""),
            ("iptables", "-A OUTPUT -p icmp --icmp-type echo-request -j DROP"),
            ("iptables", "-C OUTPUT -p icmp --icmp-type echo-request -j DROP"),
            ("iptables", "-R OUTPUT 1 -p icmp --icmp-type echo-request -j ACCEPT"),
        ],
        "expected": {},
    },
}


def resolve_ipv4_target(target: object) -> Tuple[bool, str, str]:
    """Resolve a numeric IPv4 address or hostname on the Ubuntu host.

    The guest still receives only a numeric address, so this feature does not
    require a DNS resolver inside Asterinas.  Only A/IPv4 answers are used;
    IPv6 ping remains deliberately outside the Stage14 demo.
    """
    if not isinstance(target, str):
        return False, "target must be an IPv4 address or hostname", ""
    value = target.strip()
    if not value or len(value) > 253:
        return False, "target must be an IPv4 address or hostname", ""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        hostname = value.rstrip(".")
        try:
            ascii_name = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return False, "hostname cannot be IDNA encoded", ""
        if (not ascii_name or len(ascii_name) > 253 or
                any(not HOSTNAME_LABEL_RE.fullmatch(label)
                    for label in ascii_name.split("."))):
            return False, "target must be a valid hostname or IPv4 address", ""
        try:
            answers = socket.getaddrinfo(
                ascii_name, None, socket.AF_INET, socket.SOCK_DGRAM
            )
        except socket.gaierror as exc:
            return False, f"IPv4 DNS lookup failed for {value!r}: {exc}", ""
        addresses: List[str] = []
        for answer in answers:
            sockaddr = answer[4]
            if not sockaddr:
                continue
            candidate = sockaddr[0]
            try:
                parsed = ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue
            rendered = str(parsed)
            if rendered not in addresses:
                addresses.append(rendered)
        if not addresses:
            return False, f"hostname {value!r} has no IPv4 A record", ""
        return True, "", addresses[0]
    if address.version != 4:
        return False, "only IPv4 ping probes are exposed", ""
    return True, "", str(address)


def classify_probe(target: str, rc: int) -> Tuple[str, str]:
    """Return a stable UI status and a human-readable diagnostic."""
    if rc == 0:
        return "PASS", "可达"
    if target in LOCAL_PROBE_TARGETS:
        return "FAIL", "本地拓扑不可达：检查 setup、QEMU 网卡和 OUTPUT/FORWARD 规则；可先用 Reset rules + ping"
    if rc == 1:
        return "FAIL", "无响应：外网目标需要 guest 默认路由、上行网卡和 NAT"
    return "FAIL", f"guest ping 失败（rc={rc}）"


def parse_pairs(text: str) -> Dict[str, str]:
    try:
        tokens = shlex.split(text)
    except ValueError:
        # A serial reader can observe a line while its quoted title is still
        # being written.  The next poll will see the complete line.
        return {}
    pairs: Dict[str, str] = {}
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            pairs[key] = value
    return pairs


def parse_snapshot(lines: Iterable[str]) -> Tuple[List[dict], Dict[str, dict]]:
    table = "filter"
    rules: List[dict] = []
    chains: Dict[str, dict] = {}
    for raw in lines:
        line = raw.rstrip("\r\n")
        table_match = TABLE_RE.match(line)
        if table_match:
            table = table_match.group(1)
            continue
        chain_match = CHAIN_RE.match(line)
        if chain_match:
            family = "ipv6" if chain_match.group("v6") or table.endswith("6") else "ipv4"
            chain = chain_match.group("chain")
            key = f"{family}:{table}:{chain}"
            chains[key] = {
                "family": family,
                "table": table,
                "chain": chain,
                "policy": chain_match.group("policy"),
            }
            continue
        rule_match = RULE_RE.match(line)
        if not rule_match:
            continue
        family = "ipv6" if rule_match.group("v6") or table.endswith("6") else "ipv4"
        rest = rule_match.group("rest")
        target_match = re.search(r"\btarget\s+(\S+)", rest)
        rules.append({
            "family": family,
            "table": table,
            "chain": chains.get(f"{family}:{table}:", {}).get("chain", ""),
            "number": int(rule_match.group("number")),
            "packets": int(rule_match.group("packets")),
            "bytes": int(rule_match.group("bytes")),
            "match": rest,
            "target": target_match.group(1) if target_match else "-",
        })
    # Rule lines do not repeat the chain name.  Walk the source once more with
    # the active chain so both IPv4 and IPv6 snapshots retain it in the UI.
    rules = []
    table = "filter"
    active_chain = ""
    for raw in lines:
        line = raw.rstrip("\r\n")
        table_match = TABLE_RE.match(line)
        if table_match:
            table, active_chain = table_match.group(1), ""
            continue
        chain_match = CHAIN_RE.match(line)
        if chain_match:
            active_chain = chain_match.group("chain")
            continue
        rule_match = RULE_RE.match(line)
        if not rule_match:
            continue
        family = "ipv6" if rule_match.group("v6") or table.endswith("6") else "ipv4"
        rest = rule_match.group("rest")
        target_match = re.search(r"\btarget\s+(\S+)", rest)
        rules.append({
            "family": family,
            "table": table,
            "chain": active_chain,
            "number": int(rule_match.group("number")),
            "packets": int(rule_match.group("packets")),
            "bytes": int(rule_match.group("bytes")),
            "match": rest,
            "target": target_match.group(1) if target_match else "-",
        })
    return rules, chains


def empty_state(log_path: Path) -> dict:
    return {
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "log": str(log_path),
        "complete": False,
        "connected": False,
        "topology": {
            "left": "10.0.2.2 / fd00:0:0:2::2",
            "router_left": "10.0.2.15 / fd00:0:0:2::15",
            "router_right": "10.0.3.15 / fd00:0:0:3::15",
            "right": "10.0.3.2 / fd00:0:0:3::2",
        },
        "step": {"id": "", "scenario": "", "title": "Waiting for demo-step", "status": "idle"},
        "scenarios": {name: {"name": name, "status": "PENDING"}
                      for name in ("filter", "conntrack", "nat")},
        "actions": [], "flows": [], "controls": [], "probes": [],
        "probe_presets": PROBE_PRESETS,
        "probe_suites": PROBE_SUITES,
        "probe_summary": {"passed": 0, "failed": 0, "last": None},
        "directions": DIRECTION_TARGETS,
        "lab_profiles": {
            name: {"label": profile["label"], "probe": profile.get("probe", "rule-only")}
            for name, profile in LAB_PROFILES.items()
        },
        "experiments": [],
        "experiment_summary": {"passed": 0, "failed": 0, "last": None},
        "resolutions": [],
        "rules": [], "chains": {}, "snapshots": {}, "snapshot": "waiting",
        "message": "Start demo-step in QEMU, then keep this page open.",
    }


def _bounded_append(items: List[dict], value: dict, limit: int = 80) -> None:
    items.append(value)
    del items[:-limit]


def read_state(log_path: Path, connected: bool) -> dict:
    state = empty_state(log_path)
    state["connected"] = connected
    if not log_path.exists():
        state["message"] = "Serial log does not exist yet. Start the demo-step guest."
        return state
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        state["message"] = f"Cannot read serial log: {exc}"
        return state

    snapshot_lines: Optional[List[str]] = None
    snapshot_label: Optional[str] = None
    for line in lines:
        begin = SNAPSHOT_BEGIN.match(line)
        end = SNAPSHOT_END.match(line)
        if begin:
            snapshot_label, snapshot_lines = begin.group(1), []
            continue
        if end:
            if snapshot_label == end.group(1) and snapshot_lines is not None:
                rules, chains = parse_snapshot(snapshot_lines)
                state["snapshots"][snapshot_label] = {"rules": rules, "chains": chains}
                state["rules"], state["chains"], state["snapshot"] = rules, chains, snapshot_label
            snapshot_lines, snapshot_label = None, None
            continue
        if snapshot_lines is not None:
            snapshot_lines.append(line)
            continue
        if not line.startswith(DEMO_PREFIX):
            continue
        pairs = parse_pairs(line[len(DEMO_PREFIX):])
        if pairs.get("step") and "status" in pairs:
            state["step"] = {
                "id": pairs["step"], "scenario": pairs.get("scenario", ""),
                "title": pairs.get("title", pairs["step"]), "status": pairs["status"],
            }
        scenario = pairs.get("scenario")
        if scenario in state["scenarios"]:
            state["scenarios"][scenario]["status"] = (
                "PASS" if pairs.get("phase") == "end" else "RUNNING"
            )
        if pairs.get("action"):
            action = dict(pairs)
            try:
                action["rc"] = int(action.get("rc", "-1"))
            except ValueError:
                action["rc"] = -1
            action["status"] = "PASS" if action["rc"] == 0 else "FAIL"
            _bounded_append(state["actions"], action)
        if pairs.get("flow"):
            _bounded_append(state["flows"], pairs)
        if pairs.get("control") == "rule":
            event = dict(pairs)
            try:
                event["rc"] = int(event.get("rc", "-1"))
            except ValueError:
                event["rc"] = -1
            event["status"] = "PASS" if event["rc"] == 0 else "FAIL"
            _bounded_append(state["controls"], event)
        if pairs.get("probe") == "ping":
            event = dict(pairs)
            for key in ("count", "timeout", "rc"):
                try:
                    event[key] = int(event.get(key, "-1"))
                except ValueError:
                    event[key] = -1
            event["status"], event["reason"] = classify_probe(
                event.get("target", ""), event["rc"]
            )
            event["scope"] = "local" if event.get("target") in LOCAL_PROBE_TARGETS else "external"
            _bounded_append(state["probes"], event)
        if pairs.get("complete") in ("0", "1"):
            state["complete"] = pairs["complete"] == "1"

    state["probe_summary"] = {
        "passed": sum(1 for event in state["probes"] if event.get("status") == "PASS"),
        "failed": sum(1 for event in state["probes"] if event.get("status") == "FAIL"),
        "last": state["probes"][-1] if state["probes"] else None,
    }
    if state["complete"]:
        for scenario in state["scenarios"].values():
            if scenario["status"] == "RUNNING":
                scenario["status"] = "PASS"
    state["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    if not connected:
        state["message"] = "QEMU socket is not connected; start demo-step and wait for its socket."
    elif state["complete"]:
        state["message"] = "Demo complete. You can reset it or issue a manual rule/ping probe."
    else:
        state["message"] = "Live guest state. Manual commands create a new snapshot and timeline event."
    return state


class ControlChannel:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.connection: Optional[socket.socket] = None
        self.stop = False
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        while not self.stop:
            with self.lock:
                connected = self.connection is not None
            if not connected:
                conn: Optional[socket.socket] = None
                try:
                    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    conn.settimeout(1.0)
                    conn.connect(str(self.path))
                    conn.settimeout(None)
                    with self.lock:
                        self.connection = conn
                except OSError:
                    if conn is not None:
                        conn.close()
                    time.sleep(0.5)
                    continue
            try:
                with self.lock:
                    conn = self.connection
                if conn is not None and not conn.recv(4096):
                    self._close()
            except OSError:
                self._close()

    def _close(self) -> None:
        with self.lock:
            if self.connection is not None:
                try:
                    self.connection.close()
                except OSError:
                    pass
                self.connection = None

    def send(self, command: str) -> Tuple[bool, str]:
        with self.lock:
            if self.connection is None:
                conn: Optional[socket.socket] = None
                try:
                    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    conn.settimeout(1.0)
                    conn.connect(str(self.path))
                    self.connection = conn
                except OSError:
                    if conn is not None:
                        conn.close()
                    return False, "QEMU serial socket is not connected"
            try:
                self.connection.sendall((command.rstrip("\n") + "\n").encode())
                return True, command
            except OSError as exc:
                self.connection = None
                return False, str(exc)

    def is_connected(self) -> bool:
        with self.lock:
            return self.connection is not None


def validate_rule(family: str, args: object) -> Tuple[bool, str, str]:
    if family not in ("iptables", "ip6tables"):
        return False, "family must be iptables or ip6tables", ""
    if isinstance(args, str):
        try:
            tokens = shlex.split(args)
        except ValueError as exc:
            return False, f"cannot parse arguments: {exc}", ""
    elif isinstance(args, list) and all(isinstance(item, str) for item in args):
        tokens = args
    else:
        return False, "args must be a shell-like string or string array", ""
    if not tokens or len(tokens) > 32:
        return False, "provide 1..32 arguments", ""
    for token in tokens:
        if len(token) > 96 or not TOKEN_RE.fullmatch(token):
            return False, f"unsafe or oversized token: {token!r}", ""
    operation = next((token for token in tokens if token in OPERATIONS), None)
    if operation is None:
        return False, "supported operations: -A -I -D -F -P -Z -L", ""
    tokens = [OPERATION_ALIASES.get(token, token) for token in tokens]
    table = "filter"
    for index, token in enumerate(tokens[:-1]):
        if token in ("-t", "--table"):
            table = tokens[index + 1]
    if table not in ("filter", "nat"):
        return False, "only filter and nat tables are exposed in this demo", ""
    command = family + " " + " ".join(tokens)
    return True, "", command


def validate_ping(family: object, target: object, count: object, timeout: object) -> Tuple[bool, str, str]:
    if family not in (4, "4"):
        return False, "only IPv4 ping probes are exposed", ""
    ok, error, resolved_target = resolve_ipv4_target(target)
    if not ok:
        return False, error, ""
    try:
        count_i, timeout_i = int(count), int(timeout)
    except (TypeError, ValueError):
        return False, "count and timeout must be integers", ""
    if not (1 <= count_i <= 5 and 1 <= timeout_i <= 5):
        return False, "count and timeout are limited to 1..5 seconds/packets", ""
    return True, "", f"ping4 {resolved_target} {count_i} {timeout_i}"


def validate_probe_suite(suite: object) -> Tuple[bool, str, str]:
    if suite not in PROBE_SUITES:
        return False, "suite must be local or external", ""
    return True, "", f"probe-suite {suite}"


def validate_direction(direction: object) -> Tuple[bool, str, List[str]]:
    if direction == "both":
        return True, "", list(DIRECTION_TARGETS)
    if direction not in DIRECTION_TARGETS:
        return False, "direction must be left-to-right, right-to-left, or both", []
    return True, "", [str(direction)]


def validate_lab_profile(profile: object) -> Tuple[bool, str, dict]:
    if profile not in LAB_PROFILES:
        return False, "unknown lab profile", {}
    return True, "", LAB_PROFILES[str(profile)]


def validate_expectation(value: object) -> Tuple[bool, str, Optional[Dict[str, bool]]]:
    if value not in EXPECTATION_PROFILES:
        return False, "expectation must be observe, both, left-only, right-only, or deny-both", None
    return True, "", EXPECTATION_PROFILES[str(value)]


def validate_probe_numbers(count: object, timeout: object) -> Tuple[bool, str, int, int]:
    try:
        count_i, timeout_i = int(count), int(timeout)
    except (TypeError, ValueError):
        return False, "count and timeout must be integers", 0, 0
    if not (1 <= count_i <= 4 and 1 <= timeout_i <= 5):
        return False, "directional probes allow count 1..4 and timeout 1..5", 0, 0
    return True, "", count_i, timeout_i


def run_namespace_ping(direction: str, count: int, timeout: int) -> dict:
    """Run a fixed endpoint-to-endpoint probe from the Ubuntu host.

    The dashboard is local-only, but it must not turn the HTTP API into a
    shell.  Every namespace, address and argument is selected from the
    allow-list above; only the sudo prefix is conditional on the dashboard's
    effective uid.
    """
    target = DIRECTION_TARGETS[direction]
    prefix = [] if hasattr(os, "geteuid") and os.geteuid() == 0 else ["sudo", "-n"]
    argv = prefix + [
        "ip", "netns", "exec", target["namespace"], "ping", "-4", "-n",
        "-c", str(count), "-W", str(timeout), target["target"],
    ]
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=max(8, count * timeout + 4), check=False,
        )
        output = (completed.stdout + completed.stderr).strip()
        rc = int(completed.returncode)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        output = (stdout + stderr).strip()
        rc = 124
    except OSError as exc:
        output = str(exc)
        rc = 127
    return {
        "direction": direction,
        "label": target["label"],
        "namespace": target["namespace"],
        "source": target["source"],
        "target": target["target"],
        "count": count,
        "timeout": timeout,
        "rc": rc,
        "status": "PASS" if rc == 0 else "FAIL",
        "output": output[-2400:],
    }


def counter_deltas(before: Iterable[dict], after: Iterable[dict]) -> List[dict]:
    """Join two snapshots and expose packet/byte changes per rule."""
    def key(rule: dict) -> Tuple[object, ...]:
        return (
            rule.get("family"), rule.get("table"), rule.get("chain"),
            rule.get("number"), rule.get("match"), rule.get("target"),
        )

    previous = {key(rule): rule for rule in before}
    changes: List[dict] = []
    for rule in after:
        old = previous.get(key(rule), {})
        packet_delta = int(rule.get("packets", 0)) - int(old.get("packets", 0))
        byte_delta = int(rule.get("bytes", 0)) - int(old.get("bytes", 0))
        if packet_delta or byte_delta:
            changes.append({
                "family": rule.get("family"), "table": rule.get("table"),
                "chain": rule.get("chain"), "number": rule.get("number"),
                "match": rule.get("match"), "target": rule.get("target"),
                "packets": packet_delta, "bytes": byte_delta,
            })
    return changes


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Asterinas Netfilter Control Lab</title>
<style>
:root{color-scheme:dark;--bg:#08121f;--card:#12243d;--line:#2e527d;--text:#eaf2ff;--muted:#9db5d3;--blue:#75baff;--green:#42e09a;--red:#ff7184;--gold:#ffc56f}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,var(--bg),#112a4b);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}header{padding:20px 26px 14px;border-bottom:1px solid var(--line)}h1{margin:0;font-size:24px}.sub{color:var(--muted)}main{max-width:1600px;margin:auto;padding:16px 22px 40px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{background:#12243dee;border:1px solid var(--line);border-radius:12px;padding:14px}.wide{grid-column:span 12}.half{grid-column:span 6}.third{grid-column:span 4}h2{font-size:15px;margin:0 0 10px;color:#cfe4ff}.topo{display:flex;justify-content:center;align-items:center;gap:8px;flex-wrap:wrap}.node{min-width:170px;text-align:center;background:#183554;border:1px solid #4a7db3;border-radius:9px;padding:8px 12px}.node strong{display:block;color:var(--blue);font-size:16px}.arrow{color:var(--gold);font-size:21px}.badge{border-radius:999px;padding:2px 8px;background:#294463;color:var(--muted);font-size:12px}.pass{background:#123f30;color:var(--green)}.fail{background:#471f2d;color:var(--red)}.running{background:#4c371d;color:var(--gold)}.waiting{background:#253f62;color:var(--blue)}.controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.current{flex:1;min-width:260px}button,select,input{border:1px solid #4b78ac;border-radius:7px;background:#183554;color:var(--text);padding:8px 10px;font:inherit}input{min-width:170px}button{cursor:pointer}button:hover{background:#24507b}button:disabled{opacity:.55;cursor:wait}.message{color:var(--gold);margin-top:9px}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}.route{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted)}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #2b496b;vertical-align:top}th{color:var(--muted);font-weight:500}.scroll{max-height:410px;overflow:auto}.flow{border-left:3px solid var(--blue);padding:6px 10px;margin:6px 0;background:#102039}.form{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0}.hint{color:var(--muted);font-size:12px}.error{color:var(--red);min-height:20px}.pill{display:inline-block;padding:2px 7px;border-radius:999px;background:#294463}.small{font-size:12px;color:var(--muted)}@media(max-width:950px){.half,.third{grid-column:span 12}main{padding:12px}}
</style></head><body><header><h1>Asterinas Netfilter Control Lab</h1><div class="sub">Live IPv4/IPv6 rules, counters, packet-flow events, manual rule control, and IPv4 raw-socket ping probes.</div></header>
<main><div class="grid">
<section class="card wide"><h2>Topology <span id="conn" class="badge">socket unknown</span></h2><div class="topo"><div class="node"><strong>Left host</strong><span id="left"></span></div><span class="arrow">→</span><div class="node"><strong>Asterinas router</strong><span id="router"></span></div><span class="arrow">→</span><div class="node"><strong>Right host</strong><span id="right"></span></div></div><div id="message" class="message"></div></section>
<section class="card wide"><h2>Interactive walkthrough</h2><div class="controls"><span id="current" class="current"></span><button data-command="next">Next step</button><button data-command="reset">Reset</button><select id="scenario"><option value="filter">Filter scenario</option><option value="conntrack">Conntrack scenario</option><option value="nat">NAT scenario</option><option value="all">Run all</option></select><button id="runScenario">Run scenario</button><button data-command="snapshot">Refresh snapshot</button></div></section>
<section class="card half"><h2>Manual iptables / ip6tables</h2><div class="form"><select id="ruleFamily"><option value="iptables">iptables (IPv4)</option><option value="ip6tables">ip6tables (IPv6)</option></select><input id="ruleArgs" class="mono" style="flex:1;min-width:300px" placeholder="-A OUTPUT -p icmp --icmp-type echo-request -j DROP"><button id="applyRule">Apply</button></div><div class="form"><button data-rule="-L">Refresh all tables</button><button data-rule="-F OUTPUT">Flush OUTPUT</button><button data-rule="-F FORWARD">Flush FORWARD</button><button data-rule="-Z">Zero counters</button></div><div class="form"><button data-preset="v4drop">IPv4 DROP echo</button><button data-preset="v4accept">IPv4 ACCEPT echo</button><button data-preset="v4nat">IPv4 MASQUERADE</button><button data-preset="v6drop">IPv6 FORWARD DROP</button></div><div class="form"><select id="linkedDirection"><option value="left-to-right">Probe left -> right</option><option value="right-to-left">Probe right -> left</option><option value="both">Probe both directions</option></select><select id="linkedExpectation"><option value="observe">Observe actual result</option><option value="both">Expect both pass</option><option value="left-only">Expect left -> right only</option><option value="right-only">Expect right -> left only</option><option value="deny-both">Expect both blocked</option></select><button id="applyAndProbe">Apply rule + probe</button><button id="probeCurrent">Probe current rules</button></div><div class="hint">Apply a real rule, then run endpoint pings through the same Guest. The expectation selector distinguishes a deliberate one-way DROP from an infrastructure failure; the experiment records both directions and counter deltas.</div><div class="hint">Supported subset is explicit: filter/nat, append/insert/delete/flush/policy/zero/list, check (-C), replace (-R), and the matches implemented by the guest parser. This is not a shell.</div><div id="ruleError" class="error"></div></section>
<section class="card half"><h2>IPv4 raw-socket ping probe</h2><div class="form"><select id="pingFamily"><option value="4">IPv4</option></select><input id="pingTarget" class="mono" value="1.1.1.1" placeholder="IPv4 address or hostname (e.g. baidu.com)"><label>count <input id="pingCount" type="number" min="1" max="5" value="2" style="width:65px"></label><label>timeout <input id="pingTimeout" type="number" min="1" max="5" value="2" style="width:65px"></label><button id="ping">Ping in guest</button></div><div class="form"><button id="pingLocalSuite">Run local IPv4</button><button id="pingExternalSuite">Run external IPv4</button></div><div class="hint">The dashboard resolves a hostname's IPv4 A record on Ubuntu, then sends only the numeric address to the guest's <span class="mono">/bin/ping -4</span>. Local smoke uses the isolated right endpoint; external smoke requires the reversible Ubuntu uplink helper (<span class="mono">sudo tools/net/netfilter-demo.sh setup-uplink</span>).</div><div id="pingError" class="error"></div><div class="scroll"><table><thead><tr><th>Family</th><th>Target</th><th>Packets</th><th>Timeout</th><th>Result</th></tr></thead><tbody id="probes"></tbody></table></div></section>
<section class="card wide"><h2>Live rule snapshot <select id="familyFilter"><option value="all">All families</option><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select> <select id="snapshotSelect"></select></h2><div class="scroll"><table><thead><tr><th>Family</th><th>Table</th><th>Chain</th><th>#</th><th>pkts</th><th>bytes</th><th>match</th><th>target</th></tr></thead><tbody id="rules"></tbody></table></div></section>
<section class="card wide"><h2>Linked rule → traffic experiments</h2><div class="form"><select id="labProfile"></select><select id="labDirection"><option value="both">Probe both directions</option><option value="left-to-right">Probe left -> right</option><option value="right-to-left">Probe right -> left</option></select><label>count <input id="labCount" type="number" min="1" max="4" value="2" style="width:65px"></label><label>timeout <input id="labTimeout" type="number" min="1" max="5" value="2" style="width:65px"></label><button id="applyProfile">Apply profile</button><button id="runProfile">Apply + probe</button><button id="clearExperiments">Clear experiments</button></div><div id="labHint" class="hint">Recipes are sent through the same procfs command path as manual input. ICMP forwarding profiles run real as2left/as2right probes; TCP/NAT profiles apply rules and capture the resulting rule snapshot without pretending that an ICMP ping tests TCP translation.</div><div id="experimentError" class="error"></div><div class="scroll"><table><thead><tr><th>Profile</th><th>Direction / probe</th><th>Rules / packet flow</th><th>Counter delta</th></tr></thead><tbody id="experiments"></tbody></table></div></section>
<section class="card third"><h2>Chain policies</h2><div id="chains" class="scroll"></div></section><section class="card third"><h2>Packet flows</h2><div id="flows" class="scroll"></div></section><section class="card third"><h2>Control / action timeline</h2><div id="timeline" class="scroll"></div></section>
</div></main>
<script>
const $=id=>document.getElementById(id); let state={};
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function badge(status){let c=String(status||'').toLowerCase();return `<span class="badge ${c}">${esc(status||'')}</span>`;}
function render(s){state=s;$('conn').className='badge '+(s.connected?'pass':'fail');$('conn').textContent=s.connected?'QEMU connected':'socket offline';$('left').textContent=s.topology.left;$('router').textContent=s.topology.router_left+' ↔ '+s.topology.router_right;$('right').textContent=s.topology.right;$('message').textContent=s.message;$('current').innerHTML=`Current: <b>${esc(s.step.title)}</b> ${badge(s.step.status)} <span class="small">${esc(s.step.id)}</span>`;
let selected=$('familyFilter').value;let rules=s.rules.filter(r=>selected==='all'||r.family===selected);$('rules').innerHTML=rules.length?rules.map(r=>`<tr><td>${badge(r.family)}</td><td>${esc(r.table)}</td><td>${esc(r.chain)}</td><td>${r.number}</td><td>${r.packets}</td><td>${r.bytes}</td><td class="mono">${esc(r.match)}</td><td><b>${esc(r.target)}</b></td></tr>`).join(''):`<tr><td colspan="8" class="empty">No completed /proc/netfilter_rules snapshot yet.</td></tr>`;
let snaps=Object.keys(s.snapshots);let old=$('snapshotSelect').value;$('snapshotSelect').innerHTML=`<option value="">current: ${esc(s.snapshot)}</option>`+snaps.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');if(snaps.includes(old))$('snapshotSelect').value=old;
$('chains').innerHTML=Object.values(s.chains).length?Object.values(s.chains).map(c=>`<div class="flow"><b>${esc(c.family)} ${esc(c.table)} ${esc(c.chain)}</b><br>policy ${badge(c.policy)}</div>`).join(''):'<div class="empty">No chain snapshot.</div>';
$('flows').innerHTML=s.flows.length?s.flows.slice().reverse().map(f=>`<div class="flow"><b>${esc(f.flow)}</b> ${badge(f.verdict||'')}<br><span class="mono">${esc(f.original||'')} → ${esc(f.translated||'')}</span><br>${esc(f.protocol||'')} · state ${esc(f.state||'')}</div>`).join(''):'<div class="empty">Waiting for packet-flow events.</div>';
let events=[...s.actions.map(x=>({...x,type:'action'})),...s.controls.map(x=>({...x,type:'rule'}))].slice(-60).reverse();$('timeline').innerHTML=events.length?events.map(e=>`<div class="flow"><b>${esc(e.type==='rule'?'manual rule':e.action)}</b> ${badge(e.status)}<br><span class="small">rc=${esc(e.rc)} ${esc(e.family||'')}</span></div>`).join(''):'<div class="empty">No control events.</div>';
$('probes').innerHTML=s.probes.slice().reverse().map(p=>`<tr><td>${esc(p.family)}</td><td class="mono">${esc(p.target)}</td><td>${p.count}</td><td>${p.timeout}s</td><td>${badge(p.status)} <span class="small">rc=${p.rc}</span></td></tr>`).join('')||'<tr><td colspan="5" class="empty">No probes yet.</td></tr>';
}
async function refresh(){try{let r=await fetch('/api/state');render(await r.json());}catch(e){$('message').textContent='Dashboard request failed: '+e;}}
async function control(payload){document.querySelectorAll('button').forEach(b=>b.disabled=true);$('ruleError').textContent='';$('pingError').textContent='';$('experimentError').textContent='';try{let r=await fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});let d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'control failed');await refresh();if(d.resolved_target&&d.requested_target!==d.resolved_target)$('message').textContent=`Resolved ${d.requested_target} -> ${d.resolved_target}; guest IPv4 ping sent.`;}catch(e){$('message').textContent=String(e);const box=['directional-probe','rule-and-probe','lab-profile','lab','clear-experiments'].includes(payload.command)?$('experimentError'):$('ruleError');if(box)box.textContent=String(e);}finally{document.querySelectorAll('button').forEach(b=>b.disabled=false);}}
document.querySelectorAll('[data-command]').forEach(b=>b.onclick=()=>control({command:b.dataset.command}));$('runScenario').onclick=()=>control({command:'scenario',scenario:$('scenario').value});$('familyFilter').onchange=refresh;
$('snapshotSelect').onchange=()=>{let x=$('snapshotSelect').value;if(x&&state.snapshots[x]){state.rules=state.snapshots[x].rules;state.chains=state.snapshots[x].chains;render(state);}};
document.querySelectorAll('[data-rule]').forEach(b=>b.onclick=()=>control({command:'rule',family:$('ruleFamily').value,args:b.dataset.rule}));document.querySelectorAll('[data-preset]').forEach(b=>b.onclick=()=>{let p={v4drop:['iptables','-A OUTPUT -p icmp --icmp-type echo-request -j DROP'],v4accept:['iptables','-A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT'],v4nat:['iptables','-t nat -A POSTROUTING -j MASQUERADE'],v6drop:['ip6tables','-A FORWARD -p ipv6-icmp --icmpv6-type echo-request -j DROP']}[b.dataset.preset];$('ruleFamily').value=p[0];$('ruleArgs').value=p[1];control({command:'rule',family:p[0],args:p[1]});});$('applyRule').onclick=()=>control({command:'rule',family:$('ruleFamily').value,args:$('ruleArgs').value});$('ping').onclick=()=>control({command:'ping',family:'4',target:$('pingTarget').value,count:$('pingCount').value,timeout:$('pingTimeout').value});$('pingLocalSuite').onclick=()=>control({command:'probe-suite',suite:'local'});$('pingExternalSuite').onclick=()=>control({command:'probe-suite',suite:'external'});refresh();setInterval(refresh,700);
</script>
<script>
/* Stage13E: keep the guest trace immutable while making the live view usable
 * during a long manual session.  The three clear buttons only hide browser
 * panels; they never flush a guest chain or delete evidence from the log. */
const panelCleared={chains:false,flows:false,timeline:false,probes:false};
function panelMessage(id){
  return id==='chains'?'Chain-policy view cleared (guest rules are unchanged).':
    id==='flows'?'Packet-flow view cleared (guest trace is unchanged).':
    id==='timeline'?'Action timeline cleared (guest trace is unchanged).':
    'Ping history cleared (guest trace is unchanged).';
}
function addPanelTools(){
  [['chains','Clear'],['flows','Clear'],['timeline','Clear']].forEach(([id,label])=>{
    const node=$(id); if(!node||document.querySelector(`[data-panel-tool="${id}"]`)) return;
    const h2=node.parentElement.querySelector('h2'); if(!h2) return;
    const b=document.createElement('button'); b.type='button'; b.className='panel-clear';
    b.dataset.panelTool=id; b.textContent=label;
    b.title='Hide this panel without changing guest rules or logs';
    b.onclick=()=>{panelCleared[id]=!panelCleared[id];b.textContent=panelCleared[id]?'Restore':'Clear';applyPanelClear();};
    h2.appendChild(document.createTextNode(' ')); h2.appendChild(b);
  });
  const probeTable=$('probes');
  if(probeTable && !document.querySelector('[data-panel-tool="probes"]')){
    const holder=probeTable.closest('.scroll').parentElement;
    const b=document.createElement('button'); b.type='button'; b.className='panel-clear';
    b.dataset.panelTool='probes'; b.textContent='Clear ping history';
    b.title='Hide ping rows without changing the guest trace';
    b.onclick=()=>{panelCleared.probes=!panelCleared.probes;b.textContent=panelCleared.probes?'Restore ping history':'Clear ping history';applyPanelClear();};
    holder.insertBefore(b,probeTable.closest('.scroll'));
  }
}
function addStopButton(){
  if(document.querySelector('[data-demo-stop]')) return;
  const run=$('runScenario'); if(!run) return;
  const b=document.createElement('button'); b.type='button'; b.dataset.demoStop='1';
  b.textContent='Stop guest'; b.title='Send quit to the interactive guest after complete=1 is visible';
  b.onclick=()=>{if(window.confirm('Stop the interactive guest? Use this after the demo is complete.'))control({command:'quit'});};
  run.parentElement.appendChild(b);
}
function addManualIsolationTools(){
  const zero=[...document.querySelectorAll('[data-rule]')].find(b=>b.dataset.rule==='-Z');
  if(zero && !zero.dataset.zeroWired){
    zero.dataset.zeroWired='1';
    zero.textContent='Zero filter counters';
    zero.onclick=async()=>{
      const family=$('ruleFamily').value;
      if(family!=='iptables'){
        $('ruleError').textContent='IPv4 counter reset uses iptables; select iptables (IPv4) first.';
        return;
      }
      // The current guest ABI exposes filter-chain counters reliably.  NAT
      // counter zeroing is intentionally left out until its procfs ABI is
      // made compatible; do not present two predictable EINVAL failures.
      for(const args of ['-Z INPUT','-Z FORWARD','-Z OUTPUT'])
        await control({command:'rule',family:'iptables',args});
    };
  }
  const ping=$('ping'); if(!ping||document.querySelector('[data-clean-ping]')) return;
  const clean=document.createElement('button'); clean.type='button'; clean.dataset.cleanPing='1';
  clean.textContent='Reset rules + ping';
  clean.title='Flush demo filter/NAT state, restore ACCEPT policies, then run the selected probe';
  clean.onclick=async()=>{
    await control({command:'reset'});
    await control({command:'ping',family:$('pingFamily').value,target:$('pingTarget').value,count:$('pingCount').value,timeout:$('pingTimeout').value});
  };
  ping.parentElement.appendChild(clean);
}
function applyPanelClear(){
  [['chains','Chain-policy view cleared.'],['flows','Packet-flow view cleared.'],['timeline','Action timeline cleared.'],['probes','Ping history cleared.']].forEach(([id,text])=>{
    const node=$(id); if(!node) return;
    node.style.display=panelCleared[id]?'none':'';
    const marker='panel-empty-'+id; let empty=document.getElementById(marker);
    if(panelCleared[id]){
      if(!empty){empty=document.createElement('div');empty.id=marker;empty.className='empty';const holder=id==='probes'?node.closest('.scroll').parentElement:node.parentElement;holder.appendChild(empty);}
      empty.textContent=text+' Click Restore to show it again.'; empty.style.display='block';
    }else if(empty){empty.style.display='none';}
  });
}
function renderProbeDiagnostics(s){
  const rows=(s.probes||[]).slice().reverse(); const table=$('probes');
  if(!table) return;
  table.innerHTML=rows.length?rows.map(p=>`<tr><td>${esc(p.family)}</td><td class="mono">${esc(p.target)}</td><td>${p.count}</td><td>${p.timeout}s</td><td>${badge(p.status)} <span class="small">rc=${p.rc}</span><br><span class="small">${esc(p.reason||'')}</span></td></tr>`).join(''):'<tr><td colspan="5" class="empty">No probes yet. Choose a local-topology preset first.</td></tr>';
  const summary=s.probe_summary||{}; const last=summary.last;
  const hint=$('pingError'); if(!hint) return;
  hint.className='hint';
  const resolution=(s.resolutions||[]).slice(-1)[0];
  const prefix=resolution?`Last DNS: ${resolution.requested} -> ${resolution.resolved}. `:'';
  hint.textContent=prefix+(last?(last.status==='PASS'?`Last probe passed: ${last.target}. ${summary.passed||0} passed, ${summary.failed||0} failed.`:`Last probe did not receive a reply: ${last.target}. ${last.reason||'Check IPv4 routes and firewall rules.'}`):'Local IPv4 presets exercise the isolated topology; the external preset requires the guest default route and IPv4 NAT.');
}
function addPingPresets(){
  const family=$('pingFamily'),target=$('pingTarget'); if(!family||!target||$('pingPreset')) return;
  const presets=(state.probe_presets||[]); if(!presets.length) return;
  const select=document.createElement('select'); select.id='pingPreset'; select.title='Use a deterministic local target or an external target';
  presets.forEach(p=>{const o=document.createElement('option');o.value=p.id;o.textContent=p.label+' · '+p.target;select.appendChild(o);});
  const form=target.closest('.form'); form.insertBefore(select,form.firstChild);
  const hint=document.createElement('div'); hint.id='pingNetworkHint'; hint.className='hint'; form.parentElement.insertBefore(hint,form.nextSibling);
  function sync(id){const p=presets.find(x=>x.id===id)||presets.find(x=>x.id==='v4-right');if(!p)return;family.value='4';target.value=p.target;hint.textContent=p.scope==='local'?'Local IPv4 target: requires stage2-router-topology setup and a live demo-step guest.':'External IPv4 target: requires setup-uplink and the guest default route.';}
  select.onchange=()=>sync(select.value);
  family.onchange=()=>{family.value='4';};
  select.value='v4-right'; sync(select.value);
}
const renderBase=render;
render=function(s){renderBase(s);addPanelTools();addStopButton();addManualIsolationTools();addPingPresets();renderProbeDiagnostics(s);applyPanelClear();};
addPanelTools();addStopButton();addManualIsolationTools();addPingPresets();
</script>
<script>
/* Linked experiments intentionally stay on top of the existing ABI.  Rules
 * are still written with command=rule; the extra endpoints only sequence
 * those writes, run fixed host namespace probes, and render the resulting
 * counter delta. */
let linkedLabWired=false;
function renderLinkedLab(s){
  const profile=$('labProfile');
  if(profile){
    const old=profile.value;
    profile.innerHTML=Object.entries(s.lab_profiles||{}).map(([id,p])=>`<option value="${esc(id)}" data-probe="${esc(p.probe||'rule-only')}">${esc(p.label)}</option>`).join('');
    if(old && [...profile.options].some(option=>option.value===old)) profile.value=old;
    const selected=profile.options[profile.selectedIndex];
    const isIcmp=selected && selected.dataset.probe==='icmp';
    $('labDirection').disabled=!isIcmp;
    $('labCount').disabled=!isIcmp;
    $('labTimeout').disabled=!isIcmp;
    $('runProfile').textContent=isIcmp?'Apply + directional ping':'Apply + snapshot';
    $('labHint').textContent=isIcmp?
      'This profile writes real FORWARD policy/rules, probes both isolated namespaces, then joins /proc/netfilter_rules counters and packet-flow events.':
      'This profile writes real filter/NAT rules and records the resulting snapshot. TCP port/conntrack, MASQUERADE, DNAT, and -C/-R are shown as rule-only until their matching TCP/NAT traffic harness is selected.';
  }
  const rows=(s.experiments||[]).slice().reverse();
  const table=$('experiments');
  if(table) table.innerHTML=rows.length?rows.map(e=>{
    const probes=(e.probes||[]).map(p=>`${esc(p.direction)} ${badge(p.status)} rc=${esc(p.rc)}`).join('<br>')||'rule-only';
    const flows=(e.flows||[]).slice(-6).map(f=>`${esc(f.flow||'')} ${badge(f.verdict||'')}`).join('<br>');
    const deltas=(e.counter_deltas||[]).map(d=>`${esc(d.chain||'')}#${esc(d.number)} +${esc(d.packets)} pkts/+${esc(d.bytes)} bytes`).join('<br>')||'no matched packets';
    return `<tr><td><b>${esc(e.profile_label||e.profile||'manual')}</b><br>${badge(e.status||'')}</td><td>${probes}</td><td class="mono">${esc(e.rule_summary||'')}${flows?`<hr><span class="small">${flows}</span>`:''}</td><td>${deltas}</td></tr>`;
  }).join(''):'<tr><td colspan="4" class="empty">No linked experiments yet. Apply a rule or choose a recipe.</td></tr>';
  if(linkedLabWired) return;
  linkedLabWired=true;
  const send=payload=>control(payload);
  $('applyAndProbe').onclick=()=>send({command:'rule-and-probe',family:$('ruleFamily').value,args:$('ruleArgs').value,direction:$('linkedDirection').value,expectation:$('linkedExpectation').value,count:$('labCount').value,timeout:$('labTimeout').value});
  $('probeCurrent').onclick=()=>send({command:'directional-probe',direction:$('linkedDirection').value,expectation:$('linkedExpectation').value,count:$('labCount').value,timeout:$('labTimeout').value});
  $('applyProfile').onclick=()=>send({command:'lab-profile',profile:$('labProfile').value});
  $('runProfile').onclick=()=>send({command:'lab',profile:$('labProfile').value,direction:$('labDirection').value,count:$('labCount').value,timeout:$('labTimeout').value});
  $('labProfile').onchange=()=>renderLinkedLab(s);
  $('clearExperiments').onclick=()=>send({command:'clear-experiments'});
}
const renderLinkedBase=render;
render=function(s){renderLinkedBase(s);renderLinkedLab(s);};
</script></body></html>'''


class DashboardHandler(BaseHTTPRequestHandler):
    server: "DashboardServer"

    def _json(self, value: dict, status: int = 200) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = url_path(self.path)
        if path == "/api/state":
            try:
                state = read_state(self.server.log_path, self.server.control.is_connected())
            except Exception as exc:  # keep the dashboard alive on a partial serial line
                state = empty_state(self.server.log_path)
                state["connected"] = self.server.control.is_connected()
                state["message"] = f"State reader error: {type(exc).__name__}: {exc}"
            state["resolutions"] = self.server.resolution_snapshot()
            state["experiments"] = self.server.experiment_snapshot()
            state["experiment_summary"] = {
                "passed": sum(1 for item in state["experiments"] if item.get("status") == "PASS"),
                "failed": sum(1 for item in state["experiments"] if item.get("status") == "FAIL"),
                "last": state["experiments"][-1] if state["experiments"] else None,
            }
            self._json(state)
            return
        if path in ("/", "/index.html"):
            payload = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self._json({"ok": False, "error": "not found"}, 404)

    def do_POST(self) -> None:
        if url_path(self.path) != "/api/control":
            self._json({"ok": False, "error": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"ok": False, "error": f"invalid JSON: {exc}"}, 400)
            return
        if not isinstance(data, dict):
            self._json({"ok": False, "error": "JSON body must be an object"}, 400)
            return
        command = data.get("command")
        wire = ""
        if command in ("next", "n", "reset", "r", "snapshot", "quit"):
            wire = command
        elif command == "scenario":
            scenario = data.get("scenario")
            if scenario not in ("filter", "conntrack", "nat", "all"):
                self._json({"ok": False, "error": "unknown scenario"}, 400)
                return
            wire = f"scenario {scenario}"
        elif command == "rule":
            ok, error, wire = validate_rule(data.get("family"), data.get("args"))
            if not ok:
                self._json({"ok": False, "error": error}, 400)
                return
        elif command == "ping":
            requested_target = data.get("target")
            resolved_target = ""
            ok, error, resolved_target = resolve_ipv4_target(requested_target)
            if not ok:
                self._json({"ok": False, "error": error}, 400)
                return
            ok, error, wire = validate_ping(
                data.get("family"), resolved_target,
                data.get("count"), data.get("timeout")
            )
            if not ok:
                self._json({"ok": False, "error": error}, 400)
                return
        elif command == "probe-suite":
            ok, error, wire = validate_probe_suite(data.get("suite"))
            if not ok:
                self._json({"ok": False, "error": error}, 400)
                return
        elif command == "clear-experiments":
            self.server.clear_experiments()
            self._json({"ok": True, "command": command})
            return
        elif command in ("directional-probe", "rule-and-probe", "lab-profile", "lab"):
            # These are orchestration commands, not shell passthrough.  The
            # actual rule writes continue through the same validated Guest
            # command path and the endpoint probes use the fixed namespace
            # allow-list above.
            if command in ("directional-probe", "rule-and-probe", "lab"):
                valid, error, directions = validate_direction(data.get("direction", "both"))
                if not valid:
                    self._json({"ok": False, "error": error}, 400)
                    return
                valid, error, count_i, timeout_i = validate_probe_numbers(
                    data.get("count", 2), data.get("timeout", 2)
                )
                if not valid:
                    self._json({"ok": False, "error": error}, 400)
                    return
            expected = None
            if command in ("directional-probe", "rule-and-probe"):
                valid, error, expected = validate_expectation(data.get("expectation", "observe"))
                if not valid:
                    self._json({"ok": False, "error": error}, 400)
                    return
            if command == "directional-probe":
                success, experiment = self.server.run_directional_experiment(
                    directions, count_i, timeout_i, expected=expected
                )
                self._json({"ok": success, "experiment": experiment,
                            "error": "one or more directional probes failed" if not success else ""},
                           200 if success else 424)
                return
            if command == "rule-and-probe":
                if data.get("family") != "iptables":
                    self._json({
                        "ok": False,
                        "error": "directional IPv4 probes require iptables (IPv4); apply ip6tables separately and inspect the IPv6 snapshot",
                    }, 400)
                    return
                valid, error, wire = validate_rule(data.get("family"), data.get("args"))
                if not valid:
                    self._json({"ok": False, "error": error}, 400)
                    return
                ok, result = self.server._send_guest(wire)
                if not ok:
                    self._json({"ok": False, "error": result}, 409)
                    return
                success, experiment = self.server.run_directional_experiment(
                    directions, count_i, timeout_i,
                    profile="manual-rule", profile_label=f"Manual: {wire}", rules=[wire],
                    expected=expected,
                )
                self._json({"ok": success, "command": wire, "experiment": experiment,
                            "error": "one or more directional probes failed" if not success else ""},
                           200 if success else 424)
                return
            valid, error, definition = validate_lab_profile(data.get("profile"))
            if not valid:
                self._json({"ok": False, "error": error}, 400)
                return
            profile = str(data["profile"])
            if command == "lab-profile":
                success, error, experiment = self.server.run_profile(
                    profile, [], 1, 1, probe=False
                )
            else:
                success, error, experiment = self.server.run_profile(
                    profile, directions, count_i, timeout_i, probe=True
                )
            response = {"ok": success, "experiment": experiment}
            if error:
                response["error"] = error
            elif not success:
                response["error"] = "profile expectation was not met"
            self._json(response, 200 if success else 424)
            return
        else:
            self._json({"ok": False, "error": "unsupported control command"}, 400)
            return
        ok, result = self.server.control.send(wire)
        if not ok:
            self._json({"ok": False, "error": result}, 409)
            return
        response = {"ok": True, "command": result}
        if command == "ping":
            requested_text = str(requested_target)
            self.server.record_resolution(requested_text, resolved_target)
            response.update(
                requested_target=requested_text,
                resolved_target=resolved_target,
            )
        self._json(response)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def url_path(value: str) -> str:
    return value.split("?", 1)[0]


class DashboardServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], log_path: Path, socket_path: Path):
        self.log_path = log_path
        self.control = ControlChannel(socket_path)
        self.resolution_lock = threading.Lock()
        self.resolutions: List[dict] = []
        self.resolution_log_path = log_path.with_name("netfilter-dashboard-resolution.log")
        self.experiment_lock = threading.RLock()
        self.experiments: List[dict] = []
        self.experiment_sequence = 0
        self.experiment_log_path = log_path.with_name("netfilter-dashboard-experiments.log")
        super().__init__(address, DashboardHandler)

    def record_resolution(self, requested: str, resolved: str) -> None:
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "requested": requested,
            "resolved": resolved,
        }
        with self.resolution_lock:
            self.resolutions.append(entry)
            del self.resolutions[:-40]
            try:
                self.resolution_log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.resolution_log_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except OSError:
                pass

    def resolution_snapshot(self) -> List[dict]:
        with self.resolution_lock:
            return list(self.resolutions)

    def experiment_snapshot(self) -> List[dict]:
        with self.experiment_lock:
            return list(self.experiments)

    def clear_experiments(self) -> None:
        """Clear only the dashboard's bounded experiment view.

        Guest rules, counters, serial evidence, and the JSONL audit file are
        intentionally preserved.  This is the same non-destructive behavior
        as the existing panel Clear buttons.
        """
        with self.experiment_lock:
            self.experiments.clear()

    def _record_experiment(self, event: dict) -> dict:
        with self.experiment_lock:
            self.experiment_sequence += 1
            event = dict(event)
            event.setdefault("id", self.experiment_sequence)
            event.setdefault("time", time.strftime("%Y-%m-%d %H:%M:%S"))
            self.experiments.append(event)
            del self.experiments[:-40]
            try:
                self.experiment_log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.experiment_log_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event, ensure_ascii=False) + "\n")
            except OSError:
                pass
            return event

    def _send_guest(self, command: str) -> Tuple[bool, str]:
        ok, result = self.control.send(command)
        if ok:
            # The guest command ABI is deliberately fire-and-forget.  A short
            # gap prevents a burst of recipe commands from racing fgets().
            time.sleep(0.12)
        return ok, result

    def _snapshot_rules(self) -> dict:
        return read_state(self.log_path, self.control.is_connected())

    def _apply_actions(self, actions: Iterable[Tuple[str, str]]) -> Tuple[bool, str, List[str]]:
        rendered: List[str] = []
        for family, args in actions:
            command = family if family == "reset" else f"{family} {args}"
            ok, result = self._send_guest(command)
            rendered.append(command)
            if not ok:
                return False, result, rendered
        # Ask the guest for an explicit post-configuration snapshot.  This is
        # separate from the per-rule snapshots and makes the experiment table
        # unambiguous after a multi-command recipe.
        ok, result = self._send_guest("snapshot")
        if not ok:
            return False, result, rendered
        return True, "", rendered

    def _run_directional(self, directions: Iterable[str], count: int, timeout: int) -> List[dict]:
        return [run_namespace_ping(direction, count, timeout) for direction in directions]

    def _record_experiment_result(
        self, profile: str, label: str, rules: List[str], probes: List[dict],
        before: dict, after: dict, expected: Optional[Dict[str, bool]] = None,
    ) -> dict:
        if expected is None:
            # Manual "observe" mode reports the real result without claiming
            # that a blocked direction is an infrastructure failure.
            for probe in probes:
                probe["expectation"] = "observe"
                probe["expectation_met"] = None
            status = "OBSERVE" if probes else "PASS"
        else:
            for probe in probes:
                if probe["direction"] in expected:
                    probe["expected"] = "PASS" if expected[probe["direction"]] else "BLOCK"
                    probe["expectation_met"] = (
                        (probe["rc"] == 0) == expected[probe["direction"]]
                    )
                else:
                    probe["expectation_met"] = probe["rc"] == 0
            passed = bool(probes) and all(probe["expectation_met"] for probe in probes)
            if not probes:
                passed = True
            status = "PASS" if passed else "FAIL"
        event = self._record_experiment({
            "profile": profile,
            "profile_label": label,
            "status": status,
            "rule_summary": " ; ".join(rules),
            "flows": after.get("flows", [])[-8:],
            "probes": probes,
            "counter_deltas": counter_deltas(before.get("rules", []), after.get("rules", [])),
        })
        return event

    def run_directional_experiment(
        self, directions: List[str], count: int, timeout: int,
        profile: str = "manual", profile_label: str = "Manual rules",
        rules: Optional[List[str]] = None,
        expected: Optional[Dict[str, bool]] = None,
    ) -> Tuple[bool, dict]:
        with self.experiment_lock:
            before = self._snapshot_rules()
            probes = self._run_directional(directions, count, timeout)
            self._send_guest("snapshot")
            time.sleep(0.2)
            after = self._snapshot_rules()
            event = self._record_experiment_result(
                profile, profile_label, rules or [], probes, before, after, expected
            )
            return event["status"] != "FAIL", event

    def apply_profile(self, profile: str) -> Tuple[bool, str, List[str], dict]:
        definition = LAB_PROFILES[profile]
        before = self._snapshot_rules()
        ok, error, rendered = self._apply_actions(definition["actions"])
        if not ok:
            return False, error, rendered, before
        time.sleep(0.2)
        return True, "", rendered, before

    def run_profile(
        self, profile: str, directions: List[str], count: int, timeout: int,
        probe: bool,
    ) -> Tuple[bool, str, dict]:
        definition = LAB_PROFILES[profile]
        with self.experiment_lock:
            before = self._snapshot_rules()
            ok, error, rendered = self._apply_actions(definition["actions"])
            if not ok:
                return False, error, {}
            # Directional ICMP is a valid traffic check only for the
            # forwarding-policy recipes.  TCP port/conntrack and NAT recipes
            # still get a complete rule snapshot, but must not be reported as
            # failed merely because an unrelated ICMP probe was attempted.
            probes = (
                self._run_directional(directions, count, timeout)
                if probe and definition.get("probe") == "icmp" else []
            )
            self._send_guest("snapshot")
            time.sleep(0.2)
            after = self._snapshot_rules()
            event = self._record_experiment_result(
                profile, definition["label"], rendered, probes,
                before, after, definition.get("expected"),
            )
            return event["status"] == "PASS", "", event


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--control-socket", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    print(f"Asterinas Netfilter Control Lab: http://{args.host}:{args.port}/", flush=True)
    print(f"Following log: {args.log}", flush=True)
    print(f"Controlling QEMU socket: {args.control_socket}", flush=True)
    DashboardServer((args.host, args.port), args.log, args.control_socket).serve_forever()


if __name__ == "__main__":
    main()
