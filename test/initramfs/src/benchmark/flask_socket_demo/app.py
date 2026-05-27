#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

import argparse
import os
import socket

from flask import Flask, jsonify, request


app = Flask(__name__)

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
      grid-template-columns: 320px 1fr;
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
          与实际 IPv4 地址访问、处理普通响应和大响应，并支持服务重启验证。
        </p>
      </div>
      <div class="badge">Flask on 0.0.0.0:5000</div>
    </header>

    <div class="grid">
      <section>
        <h2>测试操作</h2>
        <div class="actions">
          <button data-test="status">服务状态</button>
          <button data-test="echo">Echo 请求</button>
          <button data-test="large">64 KiB 响应</button>
          <button data-test="info">请求信息</button>
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
      }
    };

    const labels = {
      status: "服务状态",
      echo: "Echo 请求",
      large: "64 KiB 响应",
      info: "请求信息"
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

    function appendResult(name, ok, detail) {
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
        <td class="${ok ? "status-ok" : "status-bad"}">${ok ? "PASS" : "FAIL"}</td>
        <td>${detail}</td>
      `;
      document.getElementById("results").appendChild(row);
      appendLog(`${ok ? "PASS" : "FAIL"} ${labels[name]}: ${detail}`);
    }

    async function runTest(name) {
      try {
        const result = await tests[name]();
        appendResult(name, result.ok, result.detail);
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
      for (const name of ["status", "echo", "large", "info"]) {
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
