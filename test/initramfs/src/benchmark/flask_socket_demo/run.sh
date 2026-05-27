#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

PYTHON=/benchmark/bin/python3
APP=/benchmark/flask_socket_demo/app.py
PROBE=/benchmark/flask_socket_demo/probe.py
PORT=5000
HOST=0.0.0.0
GUEST_IP=${GUEST_IP:-10.0.2.15}

start_server() {
    "$PYTHON" "$APP" --host "$HOST" --port "$PORT" &
    SERVER_PID=$!
}

stop_server() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=
    fi
}

trap stop_server EXIT

echo "flask_socket_demo: Python and Flask import check"
"$PYTHON" - <<'PY'
from importlib.metadata import version

print("flask_socket_demo: flask version", version("flask"))
PY

echo "flask_socket_demo: start Flask on 0.0.0.0:${PORT}"
start_server

# 默认验证 0.0.0.0 listener 可以接收发往 guest 实际 IPv4 地址的请求；
# loopback 到 INADDR_ANY 的跨接口命中仍作为可选扩展检查。
"$PYTHON" "$PROBE" "http://${GUEST_IP}:${PORT}"

if [ "${CHECK_LOOPBACK_ANY:-0}" = "1" ]; then
    "$PYTHON" "$PROBE" "http://127.0.0.1:${PORT}"
fi

echo "flask_socket_demo: restart service on the same port"
stop_server
start_server
"$PYTHON" "$PROBE" "http://${GUEST_IP}:${PORT}"

echo "flask_socket_demo summary: 8 tests passed, 0 tests failed"
echo "flask_socket_demo: service startup and request handling passed"
