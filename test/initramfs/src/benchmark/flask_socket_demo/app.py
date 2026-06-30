#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

import argparse
import os
import socket
import struct
import time

from flask import Flask, jsonify, request


app = Flask(__name__)

NETFILTER_RULES_PATH = "/proc/netfilter_rules"
RAW_ICMP_TARGET = "127.0.0.1"
RAW_ICMP_IDENT = 0x4660
RAW_ICMP_SEQUENCE = 1
RAW_ICMP_TIMEOUT_SECONDS = 2.0


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"

    checksum = 0
    for index in range(0, len(data), 2):
        checksum += (data[index] << 8) + data[index + 1]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return (~checksum) & 0xFFFF


def raw_icmp_echo():
    payload = b"asterinas-flask-raw-icmp"
    header = struct.pack("!BBHHH", 8, 0, 0, RAW_ICMP_IDENT, RAW_ICMP_SEQUENCE)
    checksum = internet_checksum(header + payload)
    packet = struct.pack("!BBHHH", 8, 0, checksum, RAW_ICMP_IDENT, RAW_ICMP_SEQUENCE) + payload

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as raw_socket:
        raw_socket.settimeout(RAW_ICMP_TIMEOUT_SECONDS)
        raw_socket.sendto(packet, (RAW_ICMP_TARGET, 0))

        deadline = time.time() + RAW_ICMP_TIMEOUT_SECONDS
        while time.time() < deadline:
            try:
                data, address = raw_socket.recvfrom(2048)
            except socket.timeout:
                break

            if len(data) < 28:
                continue

            ip_header_len = (data[0] & 0x0F) * 4
            icmp = data[ip_header_len : ip_header_len + 8]
            if len(icmp) < 8:
                continue

            icmp_type, icmp_code, _, ident, sequence = struct.unpack("!BBHHH", icmp)
            if (
                icmp_type == 0
                and icmp_code == 0
                and ident == RAW_ICMP_IDENT
                and sequence == RAW_ICMP_SEQUENCE
            ):
                return {
                    "passed": True,
                    "detail": f"raw ICMP echo reply from {address[0]}",
                }

    return {
        "passed": False,
        "detail": "raw ICMP echo request timed out",
    }


def read_netfilter_rules():
    with open(NETFILTER_RULES_PATH, "r", encoding="utf-8") as rules:
        return rules.read()


def write_netfilter_command(command):
    with open(NETFILTER_RULES_PATH, "w", encoding="utf-8") as rules:
        rules.write(command)


def reset_netfilter_output_rules():
    write_netfilter_command("iptables -F OUTPUT")
    # 回归测试默认保留一个不会影响普通 ping 的 ICMP Echo 规则，恢复它可以避免
    # 演示页面改变后续测试环境。
    write_netfilter_command(
        "iptables -A OUTPUT -p icmp --icmp-type echo-request --icmp-id 0x0828 -j DROP"
    )


def format_netfilter_snapshot(snapshot):
    lines = snapshot.splitlines()
    if not lines:
        return "(empty)"
    return "\n".join(lines[:80])


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Asterinas Flask Socket Demo</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #18212f;
      --muted: #5f6b7a;
      --line: #d8dde6;
      --accent: #0f766e;
      --ok: #15803d;
      --bad: #b91c1c;
      --code: #111827;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    main {
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 20px 40px;
    }
    header {
      display: flex;
      justify-content: space-between;
      gap: 24px;
      align-items: flex-start;
      margin-bottom: 22px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 28px;
      line-height: 1.2;
    }
    .lead {
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
      max-width: 760px;
    }
    .badge {
      border: 1px solid var(--line);
      background: var(--panel);
      padding: 8px 12px;
      border-radius: 8px;
      white-space: nowrap;
      color: var(--accent);
      font-weight: 700;
      font-size: 14px;
    }
    .grid {
      display: grid;
      grid-template-columns: 360px 1fr;
      gap: 16px;
      align-items: start;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }
    h2 {
      margin: 0 0 14px;
      font-size: 18px;
    }
    .actions {
      display: grid;
      gap: 10px;
    }
    .group {
      border-top: 1px solid var(--line);
      padding-top: 12px;
      margin-top: 12px;
    }
    .group:first-child {
      border-top: 0;
      padding-top: 0;
      margin-top: 0;
    }
    .group h3 {
      margin: 0 0 8px;
      color: var(--muted);
      font-size: 14px;
    }
    button {
      width: 100%;
      border: 1px solid #0d9488;
      background: var(--accent);
      color: white;
      border-radius: 6px;
      padding: 10px 12px;
      font-weight: 700;
      cursor: pointer;
      text-align: left;
    }
    button.secondary {
      background: #ffffff;
      color: var(--accent);
    }
    button:disabled {
      opacity: 0.55;
      cursor: wait;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfd;
    }
    .metric strong {
      display: block;
      font-size: 22px;
      margin-bottom: 4px;
    }
    .metric span {
      color: var(--muted);
      font-size: 13px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-weight: 700;
    }
    .status-ok { color: var(--ok); font-weight: 700; }
    .status-bad { color: var(--bad); font-weight: 700; }
    pre {
      margin: 14px 0 0;
      padding: 12px;
      background: var(--code);
      color: #e5e7eb;
      border-radius: 8px;
      overflow: auto;
      min-height: 120px;
      font-size: 13px;
      line-height: 1.5;
    }
    @media (max-width: 820px) {
      header { display: block; }
      .badge { display: inline-block; margin-top: 12px; }
      .grid { grid-template-columns: 1fr; }
      .summary { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Asterinas Linux Socket 兼容性服务测试</h1>
        <p class="lead">
          该页面用于展示 Flask 服务在 Asterinas 中可以监听 0.0.0.0、通过 loopback
          与实际 IPv4 地址访问，并提供 raw socket ping 与 netfilter/iptables 的可视化验证入口。
        </p>
      </div>
      <div class="badge">Flask on 0.0.0.0:5000</div>
    </header>

    <div class="grid">
      <section>
        <h2>测试操作</h2>
        <div class="actions">
          <div class="group">
            <h3>指标一：Raw Socket / ping</h3>
            <button data-test="ping">Raw ICMP Echo</button>
          </div>
          <div class="group">
            <h3>指标二：Linux Socket 服务兼容</h3>
            <button data-test="status">服务状态</button>
            <button data-test="echo">Echo 请求</button>
            <button data-test="large">64 KiB 响应</button>
            <button data-test="info">请求信息</button>
          </div>
          <div class="group">
            <h3>指标三：netfilter / iptables</h3>
            <button data-test="netfilterList">查看规则</button>
            <button data-test="netfilterDropPing">DROP ping 生效</button>
            <button data-test="netfilterReset">恢复默认规则</button>
          </div>
          <button class="secondary" id="run-all">运行全部测试</button>
          <button class="secondary" id="clear">清空结果</button>
        </div>
      </section>

      <section>
        <h2>测试结果</h2>
        <div class="summary">
          <div class="metric"><strong id="total">0</strong><span>已运行</span></div>
          <div class="metric"><strong id="passed">0</strong><span>通过</span></div>
          <div class="metric"><strong id="failed">0</strong><span>失败</span></div>
        </div>
        <table>
          <thead>
            <tr>
              <th>测试项</th>
              <th>指标</th>
              <th>结果</th>
              <th>说明</th>
            </tr>
          </thead>
          <tbody id="results"></tbody>
        </table>
        <pre id="log">等待运行测试...</pre>
      </section>
    </div>
  </main>

  <script>
    const tests = {
      ping: async () => {
        const response = await fetch("/api/indicator1/ping");
        const data = await response.json();
        return {
          ok: response.ok && data.passed,
          detail: data.detail,
          rawLog: data.raw_log
        };
      },
      status: async () => {
        const response = await fetch("/api/status");
        const data = await response.json();
        return {
          ok: response.ok && data.status === "ok",
          detail: `service=${data.service}, bind=${data.bind}`
        };
      },
      echo: async () => {
        const response = await fetch("/echo/linux-socket");
        const data = await response.json();
        return {
          ok: response.ok && data.echo === "linux-socket",
          detail: `echo=${data.echo}`
        };
      },
      large: async () => {
        const response = await fetch("/large");
        const body = await response.text();
        return {
          ok: response.ok && body.length === 65536,
          detail: `response_size=${body.length} bytes`
        };
      },
      info: async () => {
        const response = await fetch("/request-info");
        const data = await response.json();
        return {
          ok: response.ok && Boolean(data.host),
          detail: `host=${data.host}, remote=${data.remote_addr}`
        };
      },
      netfilterList: async () => {
        const response = await fetch("/api/indicator3/rules");
        const data = await response.json();
        return {
          ok: response.ok && data.passed,
          detail: data.detail,
          rawLog: data.raw_log
        };
      },
      netfilterDropPing: async () => {
        const response = await fetch("/api/indicator3/drop-ping");
        const data = await response.json();
        return {
          ok: response.ok && data.passed,
          detail: data.detail,
          rawLog: data.raw_log
        };
      },
      netfilterReset: async () => {
        const response = await fetch("/api/indicator3/reset");
        const data = await response.json();
        return {
          ok: response.ok && data.passed,
          detail: data.detail,
          rawLog: data.raw_log
        };
      }
    };

    const labels = {
      ping: "Raw ICMP Echo",
      status: "服务状态",
      echo: "Echo 请求",
      large: "64 KiB 响应",
      info: "请求信息",
      netfilterList: "查看规则",
      netfilterDropPing: "DROP ping 生效",
      netfilterReset: "恢复默认规则"
    };

    const indicators = {
      ping: "指标一",
      status: "指标二",
      echo: "指标二",
      large: "指标二",
      info: "指标二",
      netfilterList: "指标三",
      netfilterDropPing: "指标三",
      netfilterReset: "指标三"
    };

    let total = 0;
    let passed = 0;
    let failed = 0;

    function setBusy(isBusy) {
      document.querySelectorAll("button").forEach(button => {
        button.disabled = isBusy;
      });
    }

    function updateSummary() {
      document.getElementById("total").textContent = total;
      document.getElementById("passed").textContent = passed;
      document.getElementById("failed").textContent = failed;
    }

    function appendLog(line) {
      const log = document.getElementById("log");
      if (log.textContent === "等待运行测试...") {
        log.textContent = "";
      }
      log.textContent += line + "\n";
      log.scrollTop = log.scrollHeight;
    }

    function appendResult(name, ok, detail, rawLog = "") {
      total += 1;
      if (ok) {
        passed += 1;
      } else {
        failed += 1;
      }
      updateSummary();

      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${labels[name]}</td>
        <td>${indicators[name]}</td>
        <td class="${ok ? "status-ok" : "status-bad"}">${ok ? "PASS" : "FAIL"}</td>
        <td>${detail}</td>
      `;
      document.getElementById("results").appendChild(row);
      appendLog(`${ok ? "PASS" : "FAIL"} ${labels[name]}: ${detail}`);
      if (rawLog) {
        appendLog(rawLog);
      }
    }

    async function runTest(name) {
      try {
        const result = await tests[name]();
        appendResult(name, result.ok, result.detail, result.rawLog);
      } catch (error) {
        appendResult(name, false, error.message);
      }
    }

    document.querySelectorAll("button[data-test]").forEach(button => {
      button.addEventListener("click", async () => {
        setBusy(true);
        await runTest(button.dataset.test);
        setBusy(false);
      });
    });

    document.getElementById("run-all").addEventListener("click", async () => {
      setBusy(true);
      for (const name of [
        "ping",
        "status",
        "echo",
        "large",
        "info",
        "netfilterList",
        "netfilterDropPing",
        "netfilterReset"
      ]) {
        await runTest(name);
      }
      setBusy(false);
    });

    document.getElementById("clear").addEventListener("click", () => {
      total = 0;
      passed = 0;
      failed = 0;
      updateSummary();
      document.getElementById("results").innerHTML = "";
      document.getElementById("log").textContent = "等待运行测试...";
    });
  </script>
</body>
</html>
"""


@app.get("/")
def index():
    return INDEX_HTML


@app.get("/api/status")
def api_status():
    return jsonify(
        service="flask_socket_demo",
        status="ok",
        bind="0.0.0.0:5000",
        message="Asterinas Linux socket compatibility demo",
    )


@app.get("/api/run-tests")
def api_run_tests():
    results = []
    with app.test_client() as client:
        status_response = client.get("/api/status")
        status_data = status_response.get_json()
        results.append(
            {
                "name": "服务状态",
                "passed": status_response.status_code == 200
                and status_data["status"] == "ok",
                "detail": status_data,
            }
        )

        echo_response = client.get("/echo/linux-socket")
        echo_data = echo_response.get_json()
        results.append(
            {
                "name": "Echo 请求",
                "passed": echo_response.status_code == 200
                and echo_data["echo"] == "linux-socket",
                "detail": echo_data,
            }
        )

        large_response = client.get("/large")
        results.append(
            {
                "name": "64 KiB 响应",
                "passed": large_response.status_code == 200
                and len(large_response.get_data()) == 65536,
                "detail": {"response_size": len(large_response.get_data())},
            }
        )

        info_response = client.get("/request-info")
        info_data = info_response.get_json()
        results.append(
            {
                "name": "请求信息",
                "passed": info_response.status_code == 200
                and bool(info_data["host"]),
                "detail": info_data,
            }
        )

    passed = sum(1 for item in results if item["passed"])
    return jsonify(total=len(results), passed=passed, failed=len(results) - passed, results=results)


@app.get("/api/indicator1/ping")
def api_indicator1_ping():
    try:
        result = raw_icmp_echo()
    except OSError as err:
        result = {
            "passed": False,
            "detail": f"raw socket error: {err}",
        }

    return jsonify(
        passed=result["passed"],
        detail=result["detail"],
        raw_log=(
            "[指标一 Raw Socket / ping]\n"
            f"target={RAW_ICMP_TARGET}\n"
            f"icmp_ident=0x{RAW_ICMP_IDENT:04x}\n"
            f"icmp_sequence={RAW_ICMP_SEQUENCE}\n"
            f"result={'PASS' if result['passed'] else 'FAIL'}\n"
            f"detail={result['detail']}"
        ),
    )


@app.get("/api/indicator3/rules")
def api_indicator3_rules():
    try:
        snapshot = read_netfilter_rules()
    except OSError as err:
        return jsonify(passed=False, detail=str(err)), 500

    has_filter = "table filter" in snapshot
    has_nat = "table nat" in snapshot
    return jsonify(
        passed=has_filter and has_nat,
        detail=f"filter={has_filter}, nat={has_nat}",
        raw_log=(
            "[指标三 查看规则]\n"
            "执行: cat /proc/netfilter_rules\n"
            f"filter_table={'present' if has_filter else 'missing'}\n"
            f"nat_table={'present' if has_nat else 'missing'}\n"
            "原始规则:\n"
            f"{format_netfilter_snapshot(snapshot)}"
        ),
    )


@app.get("/api/indicator3/drop-ping")
def api_indicator3_drop_ping():
    try:
        write_netfilter_command("iptables -F OUTPUT")
        before = raw_icmp_echo()
        write_netfilter_command("iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP")
        dropped = raw_icmp_echo()
        reset_netfilter_output_rules()
        restored = raw_icmp_echo()
    except OSError as err:
        return jsonify(passed=False, detail=str(err)), 500

    passed = before["passed"] and not dropped["passed"] and restored["passed"]
    return jsonify(
        passed=passed,
        detail=(
            f"before={'通' if before['passed'] else '不通'}, "
            f"after_drop={'已阻断' if not dropped['passed'] else '仍然通'}, "
            f"after_restore={'通' if restored['passed'] else '不通'}"
        ),
        raw_log=(
            "[指标三 DROP ping 生效]\n"
            "执行: iptables -F OUTPUT\n"
            f"加规则前 raw ICMP: {'PASS/通' if before['passed'] else 'FAIL/不通'} "
            f"({before['detail']})\n\n"
            "执行: iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP\n"
            f"DROP 后 raw ICMP: {'BLOCKED/不通' if not dropped['passed'] else 'UNEXPECTED PASS/仍然通'} "
            f"({dropped['detail']})\n\n"
            "执行: 恢复默认 OUTPUT 规则\n"
            f"恢复后 raw ICMP: {'PASS/通' if restored['passed'] else 'FAIL/不通'} "
            f"({restored['detail']})\n\n"
            f"结论: {'DROP 规则成功阻断 ICMP Echo Request' if passed else 'DROP 规则未按预期生效'}"
        ),
    )


@app.get("/api/indicator3/reset")
def api_indicator3_reset():
    try:
        reset_netfilter_output_rules()
        snapshot = read_netfilter_rules()
    except OSError as err:
        return jsonify(passed=False, detail=str(err)), 500

    restored = "icmp-echo-ident 0x0828" in snapshot
    return jsonify(
        passed=restored,
        detail=f"default_drop_rule={'present' if restored else 'missing'}",
        raw_log=(
            "[指标三 恢复默认规则]\n"
            "执行: iptables -F OUTPUT\n"
            "执行: iptables -A OUTPUT -p icmp --icmp-type echo-request "
            "--icmp-id 0x0828 -j DROP\n"
            f"default_drop_rule={'present' if restored else 'missing'}\n"
            "原始规则:\n"
            f"{format_netfilter_snapshot(snapshot)}"
        ),
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/echo/<value>")
def echo(value):
    return jsonify(echo=value)


@app.get("/large")
def large():
    return "A" * 65536


@app.get("/request-info")
def request_info():
    return jsonify(
        host=request.host,
        remote_addr=request.remote_addr,
        server_name=request.environ.get("SERVER_NAME"),
        server_port=request.environ.get("SERVER_PORT"),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    print(
        f"flask_socket_demo: starting pid={os.getpid()} "
        f"on {args.host}:{args.port}",
        flush=True,
    )
    print(
        "flask_socket_demo: hostname="
        f"{socket.gethostname()} loopback=127.0.0.1",
        flush=True,
    )
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
