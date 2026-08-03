#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0

# Host-side helper for the Stage8-Demo dashboard. The QEMU guest emits a
# machine-readable NETFILTER_DEMO trace; this script prepares the shared log
# directory and starts the dependency-free Python dashboard.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
DEMO_DIR=${NETFILTER_DEMO_DIR:-"$REPO_ROOT/stage-records/demo"}
LOG_FILE=${NETFILTER_DEMO_LOG:-"$DEMO_DIR/netfilter-demo-step-serial.log"}
CONTROL_SOCKET=${NETFILTER_DEMO_SOCKET:-"$DEMO_DIR/netfilter-demo-step.sock"}
NETDEV=${NETFILTER_DEMO_NETDEV:-router-tap}
ROUTER_TAP0=${NETFILTER_DEMO_TAP0:-as2tap0}
ROUTER_TAP1=${NETFILTER_DEMO_TAP1:-as2tap1}

usage() {
    cat >&2 <<EOF
Usage: $0 {prepare|serve|connect|help}

prepare  Create the demo evidence directory and print the QEMU command.
serve    Start the local Web dashboard and control buttons.
connect  Connect a terminal to the interactive demo serial socket (socat).

Defaults:
  log  $LOG_FILE
  URL  http://127.0.0.1:8080/
EOF
}

prepare() {
    mkdir -p "$DEMO_DIR"
    {
        date --iso-8601=seconds
        printf '%s\n' \
            "NETFILTER_DEMO_COMMAND: NETDEV=$NETDEV ROUTER_TAP0=$ROUTER_TAP0 ROUTER_TAP1=$ROUTER_TAP1 AUTO_TEST=demo-step CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 RELEASE=1 make run_kernel"
        printf '%s\n' \
            'NETFILTER_DEMO_DASHBOARD: python3 tools/net/netfilter-control-dashboard.py --log stage-records/demo/netfilter-demo-step-serial.log --control-socket stage-records/demo/netfilter-demo-step.sock'
    } >"$DEMO_DIR/environment.txt"
    echo "Demo directory: $DEMO_DIR"
    echo "Log file:       $LOG_FILE"
    echo
    echo 'Terminal A (Ubuntu host):'
    echo "  $0 serve"
    echo
    echo 'Terminal B (inside the Asterinas container):'
    echo '  mkdir -p stage-records/demo'
    echo "  NETDEV=$NETDEV ROUTER_TAP0=$ROUTER_TAP0 ROUTER_TAP1=$ROUTER_TAP1 \\" 
    echo '    AUTO_TEST=demo-step CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 RELEASE=1 \'
    echo '    make run_kernel 2>&1 | tee stage-records/demo/netfilter-demo-step-qemu.log'
}

serve() {
    mkdir -p "$DEMO_DIR"
    local dashboard_script=${NETFILTER_DEMO_DASHBOARD_SCRIPT:-"$SCRIPT_DIR/netfilter-control-dashboard.py"}
    exec python3 "$dashboard_script" \
        --log "$LOG_FILE" \
        --control-socket "$CONTROL_SOCKET" \
        --host "${NETFILTER_DEMO_HOST:-127.0.0.1}" \
        --port "${NETFILTER_DEMO_PORT:-8080}"
}

connect() {
    command -v socat >/dev/null 2>&1 || {
        echo "connect requires socat (sudo apt-get install -y socat)" >&2
        exit 1
    }
    exec socat -,raw,echo=0 "UNIX-CONNECT:$CONTROL_SOCKET"
}

case "${1:-help}" in
    prepare) prepare ;;
    serve) serve ;;
    connect) connect ;;
    help|-h|--help) usage ;;
    *) usage; exit 2 ;;
esac
