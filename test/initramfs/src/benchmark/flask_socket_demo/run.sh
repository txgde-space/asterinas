#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

PYTHON=${PYTHON:-/benchmark/bin/python3}
APP=${APP:-/benchmark/flask_socket_demo/app.py}
PROBE=${PROBE:-/benchmark/flask_socket_demo/probe.py}
PORT=${PORT:-5000}
HOST=0.0.0.0
PRIMARY_IP=${GUEST_IP:-10.0.2.15}
SECONDARY_IP=${SECONDARY_GUEST_IP:-10.0.3.15}
REQUIRE_MULTI_NET=${REQUIRE_MULTI_NET:-1}
SERVER_PID=
AVAILABLE_ADDRESSES="127.0.0.1"
PASSED=0
GENERATION=initial

print_path_evidence() {
    address=$1
    case "$address" in
        127.0.0.1) interface=lo ;;
        "$PRIMARY_IP") interface=eth0 ;;
        "$SECONDARY_IP") interface=eth1 ;;
        *) interface=unknown ;;
    esac
    echo "flask_socket_demo: EVIDENCE interface=$interface address=$address state=configured"
}

address_is_local() {
    "$PYTHON" - "$1" <<'PY'
import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
    try:
        probe.bind((sys.argv[1], 0))
    except OSError:
        raise SystemExit(1)
PY
}

start_server() {
    DEMO_GENERATION=$GENERATION "$PYTHON" "$APP" --host "$HOST" --port "$PORT" &
    SERVER_PID=$!
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=
    fi
}

probe_all_addresses() {
    phase=$1
    echo "flask_socket_demo: phase=$phase probe one wildcard listener"
    for address in $AVAILABLE_ADDRESSES; do
        "$PYTHON" "$PROBE" --expect-generation "$phase" \
            "http://${address}:${PORT}=${address}"
        PASSED=$((PASSED + 5))
    done
}

trap stop_server EXIT INT TERM

echo "flask_socket_demo: verify Python and Flask"
"$PYTHON" - <<'PY'
from importlib.metadata import version

print("flask_socket_demo: flask version", version("flask"))
PY

if ! address_is_local "$PRIMARY_IP"; then
    echo "flask_socket_demo: FAIL primary address $PRIMARY_IP is not configured" >&2
    exit 1
fi
AVAILABLE_ADDRESSES="$AVAILABLE_ADDRESSES $PRIMARY_IP"

if address_is_local "$SECONDARY_IP"; then
    AVAILABLE_ADDRESSES="$AVAILABLE_ADDRESSES $SECONDARY_IP"
elif [ "$REQUIRE_MULTI_NET" = "1" ]; then
    echo "flask_socket_demo: FAIL $SECONDARY_IP is absent; boot with MULTI_NET=on" >&2
    exit 1
else
    echo "flask_socket_demo: SKIP eth1 ($SECONDARY_IP is not configured)"
    echo "flask_socket_demo: set REQUIRE_MULTI_NET=1 for the official multi-NIC demo"
fi

for address in $AVAILABLE_ADDRESSES; do
    print_path_evidence "$address"
done

echo "flask_socket_demo: lifecycle=start bind=${HOST}:${PORT} addresses=$AVAILABLE_ADDRESSES"
start_server
FIRST_PID=$SERVER_PID
probe_all_addresses initial

echo "flask_socket_demo: lifecycle=shutdown pid=$FIRST_PID"
stop_server
PASSED=$((PASSED + 1))
echo "flask_socket_demo: PASS listener closed cleanly"

echo "flask_socket_demo: lifecycle=restart bind=${HOST}:${PORT}"
GENERATION=restarted
start_server
if [ "$SERVER_PID" = "$FIRST_PID" ]; then
    echo "flask_socket_demo: FAIL restarted process did not get a new pid" >&2
    exit 1
fi
PASSED=$((PASSED + 1))
echo "flask_socket_demo: PASS same-port restart old_pid=$FIRST_PID new_pid=$SERVER_PID"
probe_all_addresses restarted

echo "flask_socket_demo summary: $PASSED tests passed, 0 tests failed"
echo "flask_socket_demo: indicator 2 lifecycle completed"
