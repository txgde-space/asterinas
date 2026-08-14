#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

import argparse
import copy
import datetime
import json
import os
import socket
import socketserver
import threading
import time
import urllib.request

from flask import Flask, jsonify, make_response, request
from werkzeug.serving import WSGIRequestHandler, make_server

from dashboard import COMPETITION_HTML


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

EXPECTED_INTERFACES = (
    ("lo", "127.0.0.1"),
    ("eth0", "10.0.2.15"),
    ("eth1", "10.0.3.15"),
)
BROWSER_PATHS = (
    {
        "frontend_port": int(os.environ.get("PRIMARY_FRONTEND_PORT", "18080")),
        "guest_address": os.environ.get("GUEST_IP", "10.0.2.15"),
        "interface": "eth0",
    },
    {
        "frontend_port": int(os.environ.get("SECONDARY_FRONTEND_PORT", "18081")),
        "guest_address": os.environ.get("SECONDARY_GUEST_IP", "10.0.3.15"),
        "interface": "eth1",
    },
)
verification_lock = threading.Lock()
verification_state = {
    "completed_at": None,
    "current": "等待评委开始验证",
    "failed": 0,
    "passed": 0,
    "results": [],
    "running": False,
    "started_at": None,
    "status": "idle",
}
http_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def interface_for_address(address):
    for interface, expected_address in EXPECTED_INTERFACES:
        if address == expected_address:
            return interface
    return "unknown"


class LifecycleRequestHandler(WSGIRequestHandler):
    """将已接受套接字的地址加入 WSGI 环境"""

    def log_request(self, code="-", size="-"):
        """让终端只关注明确的演示证据。"""

    def make_environ(self):
        environ = super().make_environ()
        local_address, local_port = self.connection.getsockname()[:2]
        peer_address, peer_port = self.connection.getpeername()[:2]
        environ["ASTERINAS_LOCAL_ADDRESS"] = local_address
        environ["ASTERINAS_LOCAL_PORT"] = str(local_port)
        environ["ASTERINAS_PEER_ADDRESS"] = peer_address
        environ["ASTERINAS_PEER_PORT"] = str(peer_port)
        return environ


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


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def emit_step_evidence(step, passed, expected, observed, source="guest"):
    evidence = {
        "expected": expected,
        "observed": observed,
        "source": source,
        "status": "PASS" if passed else "FAIL",
        "step": step,
    }
    line = "flask_socket_demo: STEP_EVIDENCE " + json.dumps(
        evidence, ensure_ascii=False, separators=(",", ":")
    )
    print(line, flush=True)
    return evidence, line


def get_verification_snapshot():
    with verification_lock:
        return copy.deepcopy(verification_state)


def add_verification_result(group, name, passed, detail, duration_ms):
    result = {
        "detail": detail,
        "duration_ms": duration_ms,
        "group": group,
        "name": name,
        "status": "pass" if passed else "fail",
    }
    with verification_lock:
        verification_state["results"].append(result)
        verification_state["current"] = name
        counter = "passed" if passed else "failed"
        verification_state[counter] += 1


def run_verification_check(group, name, check_fn):
    started_at = time.monotonic()
    try:
        detail = check_fn()
        passed = True
    except Exception as error:
        detail = str(error)
        passed = False
    duration_ms = round((time.monotonic() - started_at) * 1000, 1)
    add_verification_result(group, name, passed, detail, duration_ms)


def address_is_local(address):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((address, 0))


def fetch_bytes(url, timeout=2.0):
    with http_opener.open(url, timeout=timeout) as response:
        return response.status, response.read()


def fetch_json(url, timeout=2.0):
    status, payload = fetch_bytes(url, timeout)
    return status, json.loads(payload.decode())


def verify_tcp_path(interface, address, port):
    base_url = f"http://{address}:{port}"
    status, health_result = fetch_json(base_url + "/health")
    if status != 200 or health_result.get("status") != "ok":
        raise RuntimeError(f"{interface} 健康检查失败")

    status, echo_result = fetch_json(base_url + "/echo/indicator-two")
    if status != 200 or echo_result.get("echo") != "indicator-two":
        raise RuntimeError(f"{interface} 请求响应失败")

    status, payload = fetch_bytes(base_url + "/large")
    if status != 200 or len(payload) != 65536:
        raise RuntimeError(f"{interface} 64 KiB 响应长度为 {len(payload)}")

    status, request_result = fetch_json(base_url + "/request-info")
    if status != 200 or request_result.get("local_address") != address:
        actual_address = request_result.get("local_address")
        raise RuntimeError(f"accepted socket 本地地址为 {actual_address}")

    return f"{base_url} · accepted={address}:{port} · 65536 bytes"


def verify_udp_path(interface, address):
    payload = f"asterinas-{interface}".encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.settimeout(2.0)
        receiver.bind(("0.0.0.0", 0))
        visible_address, port = receiver.getsockname()[:2]
        if visible_address != "0.0.0.0" or port == 0:
            raise RuntimeError(f"UDP 通配端点为 {visible_address}:{port}")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(payload, (address, port))
        received, _ = receiver.recvfrom(256)

    if received != payload:
        raise RuntimeError(f"{interface} UDP 数据不一致")
    return f"0.0.0.0:{port} 接收来自 {address} 的 {len(payload)} bytes"


def lifecycle_wsgi_app(_environ, start_response):
    payload = b'{"status":"ok"}'
    start_response(
        "200 OK",
        [("Content-Type", "application/json"), ("Content-Length", str(len(payload)))],
    )
    return [payload]


def wait_for_lifecycle_server(port):
    last_error = None
    for _ in range(20):
        try:
            status, result = fetch_json(f"http://127.0.0.1:{port}", timeout=0.5)
            if status == 200 and result.get("status") == "ok":
                return
        except (OSError, ValueError) as error:
            last_error = error
        time.sleep(0.05)
    raise RuntimeError(f"生命周期服务未就绪: {last_error}")


def stop_lifecycle_server(server, server_thread):
    server.shutdown()
    server_thread.join(timeout=3.0)
    server.server_close()
    if server_thread.is_alive():
        raise RuntimeError("生命周期服务未能停止")


def verify_inaddr_any_listener(snapshot):
    if snapshot["bind_host"] != "0.0.0.0":
        raise RuntimeError(f"bind 地址为 {snapshot['bind_host']}")
    if snapshot["listener_address"] != "0.0.0.0":
        raise RuntimeError(f"getsockname 地址为 {snapshot['listener_address']}")
    return (
        f"bind={snapshot['bind_host']}:{snapshot['bind_port']} · "
        f"getsockname={snapshot['listener_address']}:{snapshot['listener_port']}"
    )


def verify_implicit_listener(snapshot):
    implicit_listener = snapshot["implicit_listener"]
    if implicit_listener["address"] != "0.0.0.0" or implicit_listener["port"] == 0:
        raise RuntimeError(
            f"隐式绑定结果为 {implicit_listener['address']}:{implicit_listener['port']}"
        )
    return f"getsockname=0.0.0.0:{implicit_listener['port']}"


def verify_reuse_address(snapshot):
    if not snapshot["reuse_address"]:
        raise RuntimeError("SO_REUSEADDR 未启用")
    return "监听器已启用地址复用"


def verify_same_port_restart():
    servers = []
    try:
        first_server = make_server("0.0.0.0", 0, lifecycle_wsgi_app, threaded=True)
        first_port = first_server.socket.getsockname()[1]
        first_thread = threading.Thread(target=first_server.serve_forever, daemon=True)
        servers.append((first_server, first_thread))
        first_thread.start()
        wait_for_lifecycle_server(first_port)
        stop_lifecycle_server(first_server, first_thread)
        servers.clear()

        restarted_server = make_server(
            "0.0.0.0", first_port, lifecycle_wsgi_app, threaded=True
        )
        restarted_thread = threading.Thread(
            target=restarted_server.serve_forever, daemon=True
        )
        servers.append((restarted_server, restarted_thread))
        restarted_thread.start()
        wait_for_lifecycle_server(first_port)
        stop_lifecycle_server(restarted_server, restarted_thread)
        servers.clear()
    finally:
        for server, server_thread in servers:
            stop_lifecycle_server(server, server_thread)

    return f"0.0.0.0:{first_port} 关闭后同端口重新监听成功"


def run_verification_suite():
    try:
        with runtime_lock:
            snapshot = dict(runtime)

        run_verification_check(
            "Linux 监听语义",
            "INADDR_ANY 通配监听",
            lambda: verify_inaddr_any_listener(snapshot),
        )
        run_verification_check(
            "Linux 监听语义",
            "listen 隐式绑定",
            lambda: verify_implicit_listener(snapshot),
        )
        run_verification_check(
            "Linux 监听语义",
            "SO_REUSEADDR",
            lambda: verify_reuse_address(snapshot),
        )
        run_verification_check(
            "Linux 监听语义",
            "同端口服务重启",
            verify_same_port_restart,
        )

        for interface, address in EXPECTED_INTERFACES:
            def check_interface(interface=interface, address=address):
                address_is_local(address)
                return f"{interface} · {address} · UP"

            run_verification_check("多网卡拓扑", f"{interface} 接口可用", check_interface)

        listener_port = snapshot["listener_port"]
        for interface, address in EXPECTED_INTERFACES:
            run_verification_check(
                "TCP 跨接口服务",
                f"{interface} 通配监听访问",
                lambda interface=interface, address=address: verify_tcp_path(
                    interface, address, listener_port
                ),
            )

        for interface, address in EXPECTED_INTERFACES:
            run_verification_check(
                "UDP 跨接口收发",
                f"{interface} UDP 通配收发",
                lambda interface=interface, address=address: verify_udp_path(
                    interface, address
                ),
            )
    except Exception as error:
        add_verification_result("验证引擎", "未处理异常", False, str(error), 0.0)
    finally:
        with verification_lock:
            verification_state["completed_at"] = utc_now()
            verification_state["current"] = "验证完成"
            verification_state["running"] = False
            verification_state["status"] = (
                "pass" if verification_state["failed"] == 0 else "fail"
            )


@app.before_request
def count_request():
    with runtime_lock:
        runtime["request_count"] += 1


@app.after_request
def attach_socket_evidence(response):
    request_info = socket_request_info()
    local_address = request_info["local_address"] or "unknown"
    local_port = request_info["local_port"]
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Expose-Headers"] = (
        "Content-Length, X-Asterinas-Accepted-Address, "
        "X-Asterinas-Accepted-Port, X-Asterinas-Interface, "
        "X-Asterinas-Listener, X-Asterinas-Pid, X-Asterinas-Step-Evidence, "
        "X-Asterinas-Step-Status"
    )
    response.headers["X-Asterinas-Accepted-Address"] = local_address
    response.headers["X-Asterinas-Accepted-Port"] = str(local_port)
    response.headers["X-Asterinas-Interface"] = interface_for_address(local_address)
    response.headers["X-Asterinas-Listener"] = (
        f"{runtime['listener_address']}:{runtime['listener_port']}"
    )
    response.headers["X-Asterinas-Pid"] = str(os.getpid())

    if request.path == "/api/demo/path-proof":
        expected_interface = request.args.get("path", "unknown")
        expected_addresses = dict(EXPECTED_INTERFACES)
        expected_address = expected_addresses.get(expected_interface, "unknown")
        actual_interface = interface_for_address(local_address)
        passed = (
            expected_interface == actual_interface
            and local_address == expected_address
            and runtime["listener_address"] == "0.0.0.0"
            and local_port == runtime["listener_port"]
            and response.status_code == 200
        )
        evidence, line = emit_step_evidence(
            f"browser_{expected_interface}",
            passed,
            (
                f"hostfwd->{expected_interface} accepted="
                f"{expected_address}:{runtime['listener_port']} bytes=65536"
            ),
            (
                f"host={request_info['host']} accepted={local_address}:{local_port} "
                f"interface={actual_interface} listener="
                f"{runtime['listener_address']}:{runtime['listener_port']} "
                f"pid={os.getpid()} sent=65536"
            ),
            source="browser",
        )
        response.headers["X-Asterinas-Step-Evidence"] = line
        response.headers["X-Asterinas-Step-Status"] = evidence["status"]

    return response


@app.get("/")
def index():
    return COMPETITION_HTML


@app.get("/api/status")
def api_status():
    with runtime_lock:
        snapshot = dict(runtime)

    return jsonify(
        bind={"address": snapshot["bind_host"], "port": snapshot["bind_port"]},
        browser_paths=BROWSER_PATHS,
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


@app.get("/api/verification/status")
def api_verification_status():
    return jsonify(**get_verification_snapshot())


def execute_demo_step(step):
    with runtime_lock:
        snapshot = dict(runtime)

    if step == "wildcard_listener":
        expected = "bind=0.0.0.0 and getsockname=0.0.0.0:8080"
        observed = verify_inaddr_any_listener(snapshot)
    elif step == "implicit_listen":
        expected = "listen() without bind -> getsockname=0.0.0.0:<ephemeral>"
        observed = verify_implicit_listener(snapshot)
    elif step == "reuse_address":
        expected = "SO_REUSEADDR=1"
        observed = verify_reuse_address(snapshot)
    elif step == "loopback_tcp":
        expected = "127.0.0.1 reaches wildcard listener and returns 65536 bytes"
        observed = verify_tcp_path("lo", "127.0.0.1", snapshot["listener_port"])
    elif step == "udp_multi_interface":
        expected = "one UDP wildcard bind receives through lo, eth0 and eth1"
        observed = " | ".join(
            verify_udp_path(interface, address)
            for interface, address in EXPECTED_INTERFACES
        )
    elif step == "same_port_restart":
        expected = "close listener and bind the same port immediately"
        observed = verify_same_port_restart()
    else:
        raise ValueError(f"unknown demo step: {step}")

    return emit_step_evidence(step, True, expected, observed)


@app.post("/api/demo/step")
def api_demo_step():
    payload = request.get_json(silent=True) or {}
    step = payload.get("step", "")
    try:
        evidence, line = execute_demo_step(step)
        return jsonify(evidence=evidence, line=line)
    except Exception as error:
        evidence, line = emit_step_evidence(
            step or "unknown",
            False,
            "step-specific Linux socket invariant",
            str(error),
        )
        return jsonify(evidence=evidence, line=line), 422


@app.get("/api/demo/path-proof")
def api_demo_path_proof():
    token = request.args.get("token", "")
    if not token or len(token) > 80 or not token.replace("-", "").isalnum():
        return jsonify(error="invalid evidence token"), 400

    prefix = (token + "\n").encode()
    response = make_response(prefix + b"A" * (65536 - len(prefix)))
    response.headers["Content-Type"] = "application/octet-stream"
    return response


@app.post("/api/demo/browser-compare")
def api_demo_browser_compare():
    payload = request.get_json(silent=True) or {}
    proofs = payload.get("proofs", [])
    expected_addresses = {path["guest_address"] for path in BROWSER_PATHS}
    observed_addresses = {proof.get("accepted_address") for proof in proofs}
    observed_pids = {proof.get("pid") for proof in proofs}
    observed_listeners = {proof.get("listener") for proof in proofs}
    passed = (
        len(proofs) == 2
        and observed_addresses == expected_addresses
        and observed_pids == {os.getpid()}
        and observed_listeners
        == {f"{runtime['listener_address']}:{runtime['listener_port']}"}
        and all(proof.get("status") == "PASS" for proof in proofs)
    )
    expected = (
        "two hostfwd paths -> different accepted addresses; "
        "same PID and 0.0.0.0:8080 listener"
    )
    observed = (
        f"addresses={sorted(str(value) for value in observed_addresses)} "
        f"pids={sorted(str(value) for value in observed_pids)} "
        f"listeners={sorted(str(value) for value in observed_listeners)}"
    )
    evidence, line = emit_step_evidence(
        "browser_compare", passed, expected, observed, source="browser"
    )
    return jsonify(evidence=evidence, line=line), 200 if passed else 422


@app.post("/api/verification/run")
def api_verification_run():
    with verification_lock:
        if verification_state["running"]:
            return jsonify(**copy.deepcopy(verification_state)), 409
        verification_state.update(
            completed_at=None,
            current="准备验证环境",
            failed=0,
            passed=0,
            results=[],
            running=True,
            started_at=utc_now(),
            status="running",
        )

    verification_thread = threading.Thread(target=run_verification_suite, daemon=True)
    verification_thread.start()
    return jsonify(**get_verification_snapshot()), 202


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
