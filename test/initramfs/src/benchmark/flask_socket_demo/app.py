#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

import argparse
import datetime
import os
import socket
import socketserver
import threading

from flask import Flask, jsonify, request
from werkzeug.serving import WSGIRequestHandler, make_server


app = Flask(__name__)

runtime_lock = threading.Lock()
runtime = {
    "bind_host": None,
    "bind_port": None,
    "generation": os.environ.get("DEMO_GENERATION", "interactive"),
    "implicit_listener": None,
    "listener_address": None,
    "listener_port": None,
    "request_count": 0,
    "reuse_address": None,
    "started_at": None,
    "wait_backend": getattr(socketserver, "_ServerSelector").__name__,
}


class LifecycleRequestHandler(WSGIRequestHandler):
    """将已接受套接字的地址加入 WSGI 环境"""

    def make_environ(self):
        environ = super().make_environ()
        local_address, local_port = self.connection.getsockname()[:2]
        peer_address, peer_port = self.connection.getpeername()[:2]
        environ["ASTERINAS_LOCAL_ADDRESS"] = local_address
        environ["ASTERINAS_LOCAL_PORT"] = str(local_port)
        environ["ASTERINAS_PEER_ADDRESS"] = peer_address
        environ["ASTERINAS_PEER_PORT"] = str(peer_port)
        return environ


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Asterinas Linux Web 应用生命周期</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f6f8;
      --surface: #ffffff;
      --text: #17202a;
      --muted: #5f6b76;
      --line: #d5dce3;
      --teal: #087f74;
      --green: #237a3b;
      --amber: #9a6700;
      --red: #b42318;
      --code: #202934;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }
    header {
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }
    .header-inner, main { max-width: 1120px; margin: 0 auto; padding: 22px 20px; }
    .header-inner { display: flex; align-items: center; justify-content: space-between; gap: 20px; }
    h1 { margin: 0 0 5px; font-size: 24px; line-height: 1.25; }
    .subtitle { margin: 0; color: var(--muted); font-size: 14px; }
    .state { display: flex; align-items: center; gap: 8px; font-weight: 700; white-space: nowrap; }
    .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--green); }
    main { padding-top: 18px; padding-bottom: 34px; }
    section { border-bottom: 1px solid var(--line); padding: 18px 0; }
    section:first-child { padding-top: 0; }
    h2 { margin: 0 0 12px; font-size: 17px; }
    .metrics { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 1px; background: var(--line); border: 1px solid var(--line); }
    .metric { min-width: 0; padding: 13px; background: var(--surface); }
    .metric span { display: block; margin-bottom: 5px; color: var(--muted); font-size: 12px; }
    .metric strong { display: block; overflow-wrap: anywhere; font-size: 15px; }
    .lifecycle { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 8px; }
    .phase { min-height: 108px; border: 1px solid var(--line); border-radius: 6px; padding: 11px; background: var(--surface); }
    .phase b { display: block; margin-bottom: 8px; color: var(--teal); font-size: 13px; }
    .phase code { display: block; color: var(--code); overflow-wrap: anywhere; font-size: 12px; line-height: 1.5; }
    .phase.done { border-top: 3px solid var(--green); }
    .routes { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
    .address-list { display: grid; gap: 8px; }
    .address { display: grid; grid-template-columns: 74px 1fr; gap: 10px; align-items: center; padding: 9px 10px; border-left: 3px solid var(--teal); background: var(--surface); }
    .address span { color: var(--muted); font-size: 13px; }
    .address code { overflow-wrap: anywhere; }
    .actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    button { min-height: 38px; border: 1px solid var(--teal); border-radius: 6px; background: var(--surface); color: var(--teal); cursor: pointer; font-weight: 700; }
    button:hover { background: #edf8f6; }
    button:disabled { cursor: wait; opacity: .55; }
    table { width: 100%; border-collapse: collapse; background: var(--surface); font-size: 13px; }
    th, td { padding: 9px 10px; border: 1px solid var(--line); text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { background: #eef1f4; color: var(--muted); font-weight: 700; }
    .pass { color: var(--green); font-weight: 700; }
    .fail { color: var(--red); font-weight: 700; }
    pre { min-height: 82px; margin: 10px 0 0; padding: 12px; overflow: auto; border: 1px solid var(--line); background: var(--code); color: #f4f7fa; font-size: 12px; line-height: 1.5; }
    @media (max-width: 820px) {
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .lifecycle { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .routes { grid-template-columns: 1fr; }
    }
    @media (max-width: 520px) {
      .header-inner { align-items: flex-start; flex-direction: column; }
      .metrics, .lifecycle, .actions { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div>
        <h1>Flask on Asterinas</h1>
        <p class="subtitle">指标二 · Linux 网络接口语义兼容</p>
      </div>
      <div class="state"><span class="dot"></span><span>服务运行中</span></div>
    </div>
  </header>
  <main>
    <section>
      <h2>当前进程</h2>
      <div class="metrics">
        <div class="metric"><span>PID</span><strong id="pid">-</strong></div>
        <div class="metric"><span>监听 socket getsockname()</span><strong id="listener">-</strong></div>
        <div class="metric"><span>隐式 listen() 绑定</span><strong id="implicit-listener">-</strong></div>
        <div class="metric"><span>SO_REUSEADDR</span><strong id="reuse">-</strong></div>
        <div class="metric"><span>进程代次 / 请求数</span><strong id="generation">-</strong></div>
      </div>
    </section>

    <section>
      <h2>Web 应用生命周期</h2>
      <div class="lifecycle">
        <div class="phase done"><b>1 · Socket</b><code>AF_INET<br>SOCK_STREAM<br>SO_REUSEADDR=1</code></div>
        <div class="phase done"><b>2 · Bind</b><code>0.0.0.0:5000<br>INADDR_ANY</code></div>
        <div class="phase done"><b>3 · Listen</b><code>一个用户 fd<br>多接口通配绑定</code></div>
        <div class="phase done"><b>4 · Wait</b><code id="wait-backend">serve_forever</code></div>
        <div class="phase done"><b>5 · Accept / I/O</b><code>accept<br>read / write<br>close</code></div>
        <div class="phase done"><b>6 · Restart</b><code id="restart-state">close listener<br>等待同端口重启</code></div>
      </div>
    </section>

    <section class="routes">
      <div>
        <h2>同一通配监听的访问路径</h2>
        <div class="address-list">
          <div class="address"><span>lo</span><code>http://127.0.0.1:5000</code></div>
          <div class="address"><span>eth0</span><code>http://10.0.2.15:5000</code></div>
          <div class="address"><span>eth1</span><code>http://10.0.3.15:5000</code></div>
        </div>
      </div>
      <div>
        <h2>当前入口功能验证</h2>
        <div class="actions">
          <button data-path="/health">健康检查</button>
          <button data-path="/echo/linux-socket">请求与响应</button>
          <button data-path="/large">64 KiB 响应</button>
          <button data-path="/request-info">实际 socket 地址</button>
        </div>
        <pre id="output">等待操作</pre>
      </div>
    </section>

    <section>
      <h2>最近一次已接受连接</h2>
      <table>
        <thead><tr><th>请求 Host</th><th>accepted socket 本地地址</th><th>客户端地址</th><th>结果</th></tr></thead>
        <tbody id="last-request"><tr><td colspan="4">尚无请求</td></tr></tbody>
      </table>
    </section>
  </main>
  <script>
    const output = document.getElementById("output");

    async function loadStatus() {
      const response = await fetch("/api/status", { cache: "no-store" });
      const data = await response.json();
      document.getElementById("pid").textContent = data.pid;
      document.getElementById("listener").textContent = `${data.listener.address}:${data.listener.port}`;
      document.getElementById("implicit-listener").textContent = `${data.implicit_listener.address}:${data.implicit_listener.port}`;
      document.getElementById("reuse").textContent = data.listener.reuse_address ? "enabled" : "disabled";
      document.getElementById("generation").textContent = `${data.generation} / ${data.request_count}`;
      document.getElementById("wait-backend").textContent = `${data.wait_backend}\naccept wait`;
      document.getElementById("restart-state").textContent = data.generation === "restarted"
        ? "listener 已关闭\n同端口重新 bind 成功"
        : "close listener\n等待同端口重启";
    }

    async function runCheck(button) {
      button.disabled = true;
      try {
        const response = await fetch(button.dataset.path, { cache: "no-store" });
        const body = await response.text();
        const size = new TextEncoder().encode(body).length;
        output.textContent = `${button.dataset.path}\nHTTP ${response.status}\n${size} bytes\n${body.slice(0, 600)}`;

        const infoResponse = await fetch("/request-info", { cache: "no-store" });
        const info = await infoResponse.json();
        const row = document.createElement("tr");
        const values = [
          info.host,
          `${info.local_address}:${info.local_port}`,
          `${info.peer_address}:${info.peer_port}`,
          response.ok ? "PASS" : "FAIL",
        ];
        values.forEach((value, index) => {
          const cell = document.createElement("td");
          cell.textContent = value;
          if (index === values.length - 1) {
            cell.className = response.ok ? "pass" : "fail";
          }
          row.appendChild(cell);
        });
        document.getElementById("last-request").replaceChildren(row);
        await loadStatus();
      } catch (error) {
        output.textContent = `FAIL\n${error}`;
      } finally {
        button.disabled = false;
      }
    }

    document.querySelectorAll("button[data-path]").forEach((button) => {
      button.addEventListener("click", () => runCheck(button));
    });
    loadStatus().catch((error) => { output.textContent = `FAIL\n${error}`; });
  </script>
</body>
</html>
"""


def socket_request_info():
    return {
        "host": request.host,
        "local_address": request.environ.get("ASTERINAS_LOCAL_ADDRESS"),
        "local_port": int(request.environ.get("ASTERINAS_LOCAL_PORT", 0)),
        "peer_address": request.environ.get("ASTERINAS_PEER_ADDRESS"),
        "peer_port": int(request.environ.get("ASTERINAS_PEER_PORT", 0)),
        "server_name": request.environ.get("SERVER_NAME"),
        "server_port": int(request.environ.get("SERVER_PORT", 0)),
    }


def check_implicit_listen_binding():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as implicit_listener:
        implicit_listener.listen(1)
        address, port = implicit_listener.getsockname()[:2]
        if address != "0.0.0.0" or port == 0:
            raise RuntimeError(
                f"implicit listen binding returned unexpected address {address}:{port}"
            )
        return {"address": address, "port": port}


@app.before_request
def count_request():
    with runtime_lock:
        runtime["request_count"] += 1


@app.get("/")
def index():
    return INDEX_HTML


@app.get("/api/status")
def api_status():
    with runtime_lock:
        snapshot = dict(runtime)

    return jsonify(
        bind={"address": snapshot["bind_host"], "port": snapshot["bind_port"]},
        generation=snapshot["generation"],
        implicit_listener=snapshot["implicit_listener"],
        indicator="linux_network_interface_semantics",
        listener={
            "address": snapshot["listener_address"],
            "port": snapshot["listener_port"],
            "reuse_address": bool(snapshot["reuse_address"]),
        },
        pid=os.getpid(),
        request_count=snapshot["request_count"],
        service="flask_socket_demo",
        started_at=snapshot["started_at"],
        status="ok",
        wait_backend=snapshot["wait_backend"],
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
    return jsonify(**socket_request_info())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    server = make_server(
        args.host,
        args.port,
        app,
        threaded=True,
        request_handler=LifecycleRequestHandler,
    )
    listener_address, listener_port = server.socket.getsockname()[:2]
    reuse_address = server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
    implicit_listener = check_implicit_listen_binding()

    with runtime_lock:
        runtime.update(
            bind_host=args.host,
            bind_port=args.port,
            implicit_listener=implicit_listener,
            listener_address=listener_address,
            listener_port=listener_port,
            reuse_address=reuse_address,
            started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

    print(
        f"flask_socket_demo: pid={os.getpid()} bind={args.host}:{args.port} "
        f"getsockname={listener_address}:{listener_port} "
        f"implicit_listen={implicit_listener['address']}:{implicit_listener['port']} "
        f"reuseaddr={reuse_address} generation={runtime['generation']} "
        f"wait={runtime['wait_backend']}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
