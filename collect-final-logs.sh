#!/usr/bin/env bash

# Collect one canonical set of Asterinas network-extension verification logs.
# Run this script on the Ubuntu VMware guest, outside the build container.

set -Eeuo pipefail

REPO=${ASTERINAS_REPO:-"$HOME/桌面/asterinas"}
SHARE=${ASTERINAS_SHARE:-/mnt/hgfs/asterinas-share}
IMAGE=${ASTERINAS_IMAGE:-docker.io/asterinas/asterinas:0.18.0-20260603}
LOG_ROOT=${ASTERINAS_FINAL_LOGS:-"$REPO/final-logs"}
LOG_REL=
TOPOLOGY="$REPO/tools/net/stage2-router-topology.sh"
DEMO="$REPO/tools/net/netfilter-demo.sh"
UPLINK="$REPO/tools/net/netfilter-external-uplink.sh"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

require_repo() {
    [ -f "$REPO/Makefile" ] || die "repository not found: $REPO"
    [ -f "$TOPOLOGY" ] || die "topology helper not found: $TOPOLOGY"
    case "$LOG_ROOT" in
        "$REPO"/*) LOG_REL=${LOG_ROOT#"$REPO"/} ;;
        *) die "ASTERINAS_FINAL_LOGS must be inside the repository: $LOG_ROOT" ;;
    esac
    [[ "$LOG_REL" =~ ^[A-Za-z0-9._/-]+$ ]] || \
        die "log directory contains unsupported characters: $LOG_REL"
    mkdir -p \
        "$LOG_ROOT/environment" \
        "$LOG_ROOT/regression" \
        "$LOG_ROOT/qemu" \
        "$LOG_ROOT/scenarios" \
        "$LOG_ROOT/demo" \
        "$LOG_ROOT/external"
    # Archives and cross-platform copies may lose executable mode bits.
    chmod +x "$TOPOLOGY" "$DEMO" "$UPLINK" 2>/dev/null || true
}

container_base() {
    sudo podman run --rm -it --privileged \
        --network=host \
        -v /dev:/dev \
        -v "$REPO:/root/asterinas" \
        -e HTTP_PROXY=http://192.168.255.1:7897 \
        -e HTTPS_PROXY=http://192.168.255.1:7897 \
        -e ALL_PROXY=http://192.168.255.1:7897 \
        -e RUSTUP_DIST_SERVER=https://rsproxy.cn \
        -e RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup \
        "$@"
}

prepare() {
    require_repo
    sudo -v
    {
        date --iso-8601=seconds
        printf 'repository=%s\n' "$REPO"
        printf 'image=%s\n' "$IMAGE"
        git -C "$REPO" rev-parse HEAD
        git -C "$REPO" status --short
        uname -a
        podman --version
        qemu-system-x86_64 --version | head -n 1
        ip -4 route show
        ip -6 route show
    } >"$LOG_ROOT/environment/baseline.txt" 2>&1

    sudo bash "$UPLINK" teardown >/dev/null 2>&1 || true
    sudo "$TOPOLOGY" teardown >/dev/null 2>&1 || true
    sudo "$TOPOLOGY" setup \
        2>&1 | tee "$LOG_ROOT/environment/topology-setup.log"
    sudo "$TOPOLOGY" show \
        2>&1 | tee "$LOG_ROOT/environment/topology-state.log"

    echo "Prepared: $LOG_ROOT"
}

regression() {
    require_repo
    container_base \
        -e AUTO_TEST=regression \
        -e CONSOLE=ttyS0 \
        -e LOG_LEVEL=error \
        -e ENABLE_KVM=1 \
        -e SMP=4 \
        -e RELEASE=1 \
        "$IMAGE" bash -lc \
        "cd /root/asterinas && set -o pipefail && make run_kernel 2>&1 | tee '$LOG_REL/regression/full-regression.log'"
}

scenario_flags() {
    case "$1" in
        forward)
            echo 'netfilter.ipv4_forward=on netfilter.ipv6_forward=on'
            ;;
        icmp-masquerade)
            echo 'netfilter.ipv4_forward=on netfilter.stage3_icmp_masquerade=on'
            ;;
        icmp-dnat)
            echo 'netfilter.ipv4_forward=on netfilter.stage3_icmp_dnat=on'
            ;;
        forward-drop)
            echo 'netfilter.ipv4_forward=on netfilter.stage3_icmp_forward_drop=on'
            ;;
        tcp-masquerade)
            echo 'netfilter.ipv4_forward=on netfilter.stage4_tcp_masquerade=on'
            ;;
        udp-masquerade)
            echo 'netfilter.ipv4_forward=on netfilter.stage4_udp_masquerade=on'
            ;;
        tcp-dnat)
            echo 'netfilter.ipv4_forward=on netfilter.stage4_tcp_dnat=on'
            ;;
        conntrack)
            echo 'netfilter.ipv4_forward=on netfilter.stage4_tcp_masquerade=on netfilter.stage6_tcp_conntrack_policy=on'
            ;;
        ipv6-forward-drop)
            echo 'netfilter.ipv6_forward=on netfilter.stage11_ipv6_forward_drop=on'
            ;;
        ipv6-masquerade)
            echo 'netfilter.ipv6_forward=on netfilter.stage12_ipv6_snat=on'
            ;;
        ipv6-dnat)
            echo 'netfilter.ipv6_forward=on netfilter.stage12_ipv6_dnat=on'
            ;;
        demo)
            echo 'netfilter.ipv4_forward=on netfilter.ipv6_forward=on'
            ;;
        *)
            die "unknown boot scenario: $1"
            ;;
    esac
}

boot() {
    require_repo
    local name=${1:?scenario required}
    local flags
    flags=$(scenario_flags "$name")

    if [ "$name" = demo ]; then
        container_base \
            -e NETDEV=router-tap \
            -e ROUTER_TAP0=as2tap0 \
            -e ROUTER_TAP1=as2tap1 \
            -e AUTO_TEST=demo-step \
            -e CONSOLE=ttyS0 \
            -e LOG_LEVEL=error \
            -e ENABLE_KVM=1 \
            -e SMP=4 \
            -e RELEASE=1 \
            -e "NETFILTER_DEMO_SOCKET=$LOG_REL/demo/netfilter-demo.sock" \
            -e "NETFILTER_DEMO_SERIAL_LOG=$LOG_REL/demo/netfilter-demo-serial.log" \
            -e "EXTRA_KCMD_ARGS=--kcmd-args=\"$flags\"" \
            "$IMAGE" bash -lc \
            "cd /root/asterinas && set -o pipefail && make run_kernel 2>&1 | tee '$LOG_REL/qemu/demo.log'"
    else
        container_base \
            -e NETDEV=router-tap \
            -e ROUTER_TAP0=as2tap0 \
            -e ROUTER_TAP1=as2tap1 \
            -e CONSOLE=ttyS0 \
            -e LOG_LEVEL=error \
            -e ENABLE_KVM=1 \
            -e SMP=4 \
            -e RELEASE=1 \
            -e "EXTRA_KCMD_ARGS=--kcmd-args=\"$flags\"" \
            "$IMAGE" bash -lc \
            "cd /root/asterinas && set -o pipefail && make run_kernel 2>&1 | tee '$LOG_REL/qemu/$name.log'"
    fi
}

scenario_test_command() {
    case "$1" in
        forward) echo 'test test-ipv6 test-ipv6-forward' ;;
        icmp-masquerade) echo 'test-nat' ;;
        icmp-dnat) echo 'test-dnat' ;;
        forward-drop) echo 'test-forward-drop' ;;
        tcp-masquerade|conntrack) echo 'test-tcp-nat' ;;
        udp-masquerade) echo 'test-udp-nat' ;;
        tcp-dnat) echo 'test-tcp-dnat' ;;
        ipv6-forward-drop) echo 'test-ipv6-forward-drop' ;;
        ipv6-masquerade) echo 'test-ipv6-snat' ;;
        ipv6-dnat) echo 'test-ipv6-dnat' ;;
        *) die "unknown test scenario: $1" ;;
    esac
}

test_scenario() {
    require_repo
    local name=${1:?scenario required}
    local command rc=0

    for command in $(scenario_test_command "$name"); do
        echo "===== $name / $command =====" | tee -a "$LOG_ROOT/scenarios/$name.log"
        if ! sudo "$TOPOLOGY" "$command" \
            2>&1 | tee -a "$LOG_ROOT/scenarios/$name.log"; then
            rc=1
        fi
    done
    return "$rc"
}

serve_dashboard() {
    require_repo
    NETFILTER_DEMO_DIR="$LOG_ROOT/demo" \
    NETFILTER_DEMO_LOG="$LOG_ROOT/demo/netfilter-demo-serial.log" \
    NETFILTER_DEMO_SOCKET="$LOG_ROOT/demo/netfilter-demo.sock" \
        bash "$DEMO" serve
}

dashboard_control() {
    local payload=$1
    curl -fsS -X POST http://127.0.0.1:8080/api/control \
        -H 'Content-Type: application/json' \
        -d "$payload"
}

dashboard_probes() {
    require_repo
    mkdir -p "$LOG_ROOT/demo"
    local state_file="$LOG_ROOT/demo/dashboard-state-before-probes.json"

    if ! curl -fsS http://127.0.0.1:8080/api/state >"$state_file"; then
        die "dashboard is not reachable; run './collect-final-logs.sh serve' in terminal B"
    fi
    if ! grep -q '"connected"[[:space:]]*:[[:space:]]*true' "$state_file"; then
        die "dashboard is running but the demo guest is not connected; run './collect-final-logs.sh boot demo' in terminal A, wait for final-logs/demo/netfilter-demo.sock, then restart serve in terminal B"
    fi

    {
        date --iso-8601=seconds
        echo '--- dashboard state ---'
        cat "$state_file"
        echo
        echo '--- local IPv4 probe ---'
        dashboard_control '{"command":"ping","family":"4","target":"10.0.2.2","count":2,"timeout":2}'
        echo
        sleep 6
        echo '--- external numeric IPv4 probe ---'
        dashboard_control '{"command":"ping","family":"4","target":"1.1.1.1","count":2,"timeout":3}'
        echo
        sleep 8
        echo '--- external domain probe ---'
        dashboard_control '{"command":"ping","family":"4","target":"baidu.com","count":2,"timeout":3}'
        echo
        sleep 8
        echo '--- dashboard state after probes ---'
        curl -fsS http://127.0.0.1:8080/api/state
        echo
    } 2>&1 | tee "$LOG_ROOT/demo/raw-socket-ping-probes.log"
}

external_setup() {
    require_repo
    sudo bash "$UPLINK" teardown >/dev/null 2>&1 || true
    sudo bash "$DEMO" setup-uplink \
        2>&1 | tee "$LOG_ROOT/external/uplink-setup.log"
    sudo bash "$DEMO" uplink-status \
        2>&1 | tee "$LOG_ROOT/external/uplink-status.log"
    sudo bash "$UPLINK" test-ipv4 \
        2>&1 | tee "$LOG_ROOT/external/ipv4-numeric-ping.log"
    {
        echo '--- Ubuntu IPv4 DNS resolution ---'
        getent ahostsv4 baidu.com
        getent ahostsv4 qq.com
    } 2>&1 | tee "$LOG_ROOT/external/domain-resolution.log"
}

archive_logs() {
    require_repo
    mkdir -p "$SHARE/archives"
    local timestamp archive
    timestamp=$(date +%Y%m%d-%H%M%S)
    archive="$SHARE/archives/asterinas-final-logs-$timestamp.tar.gz"

    {
        date --iso-8601=seconds
        git -C "$REPO" rev-parse HEAD
        find "$LOG_ROOT" -type f -printf '%P  %s bytes\n' | sort
    } >"$LOG_ROOT/MANIFEST.txt"

    tar -czf "$archive" -C "$REPO" "$(basename "$LOG_ROOT")"
    sha256sum "$archive" | tee "$archive.sha256"
    ls -lh "$archive" "$archive.sha256"
    echo "Submit these two files to Codex."
}

usage() {
    cat <<'EOF'
Usage: collect-final-logs.sh COMMAND [SCENARIO]

Commands:
  prepare                  Capture environment and create the isolated topology.
  regression               Run the full regression suite in the official container.
  boot SCENARIO            Boot QEMU in terminal A; leave it running.
  test SCENARIO            Run the matching host-side test in terminal B.
  serve                    Serve the dashboard in a host terminal.
  dashboard-probes         Submit local, external-IP and domain probes to the dashboard.
  external-setup           Configure reversible IPv4 uplink and record diagnostics.
  archive                  Archive final-logs to the VMware shared folder.

Scenarios:
  forward, icmp-masquerade, icmp-dnat, forward-drop,
  tcp-masquerade, udp-masquerade, tcp-dnat, conntrack,
  ipv6-forward-drop, ipv6-masquerade, ipv6-dnat, demo

For each non-demo scenario:
  terminal A: ./collect-final-logs.sh boot SCENARIO
  terminal B: ./collect-final-logs.sh test SCENARIO
Stop QEMU in terminal A after terminal B reports success, then continue.

For dashboard and raw-socket probes:
  terminal A: ./collect-final-logs.sh boot demo
  terminal B: ./collect-final-logs.sh serve
  terminal C: ./collect-final-logs.sh external-setup
              ./collect-final-logs.sh dashboard-probes

Do not git-add final-logs/. Archive it and submit the archive separately.
EOF
}

case "${1:-help}" in
    prepare) prepare ;;
    regression) regression ;;
    boot) boot "${2:-}" ;;
    test) test_scenario "${2:-}" ;;
    serve) serve_dashboard ;;
    dashboard-probes) dashboard_probes ;;
    external-setup) external_setup ;;
    archive) archive_logs ;;
    help|-h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
