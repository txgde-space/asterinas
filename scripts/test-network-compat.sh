#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK_DIR="${ROOT_DIR}/test/initramfs/src/regression/network"
COMMON_DIR="${ROOT_DIR}/test/initramfs/src/regression/common"

TESTS=(
  linux_socket_compat_common
  linux_socket_compat
  icmp_raw_socket
  netfilter_rules
  iptables
  listen_autobind
  inaddr_any
  getsockname_any
  localhost_loopback
  tcp_accept_model
  ipv6_any
  socket_buffer_defaults
  socket_readiness
  tcp_reuseaddr
  tcp_wrapped_buffer_io
)

usage() {
  cat <<'EOF'
Usage:
  scripts/test-network-compat.sh [compile|list|podman-compile|kernel|flask-demo]

Modes:
  compile         Compile only the network compatibility tests added for this work.
  list            Print the selected test names.
  podman-compile  Run compile mode inside the Asterinas Podman build image.
  kernel          Run compile mode, then build the kernel inside the Podman image.
  flask-demo      Run the optional Flask service demo inside an Asterinas guest.

This script intentionally does not run full AUTO_TEST=regression, because the
upstream regression runner executes every regression category and network test.
EOF
}

compile_selected_tests() {
  local out_dir
  out_dir="$(mktemp -d "${TMPDIR:-/tmp}/asterinas-network-compat.XXXXXX")"
  trap "rm -rf '${out_dir}'" EXIT

  echo "Compiling selected network compatibility tests into ${out_dir}"
  for test_name in "${TESTS[@]}"; do
    local src="${NETWORK_DIR}/${test_name}.c"
    local out="${out_dir}/${test_name}"

    if [[ ! -f "${src}" ]]; then
      echo "missing test source: ${src}" >&2
      exit 1
    fi

    echo "  CC ${test_name}"
    gcc -Wall -Werror -D__asterinas__ -I"${COMMON_DIR}" "${src}" -o "${out}"
  done

  echo "All selected network compatibility tests compiled successfully."
}

run_podman() {
  local inner_cmd="$1"
  sudo podman run --rm --privileged \
    --network=host \
    -v /dev:/dev \
    -v "${ROOT_DIR}:/root/asterinas" \
    docker.io/asterinas/asterinas:0.18.0-20260603 \
    bash -lc "cd /root/asterinas && ${inner_cmd}"
}

mode="${1:-compile}"

case "${mode}" in
  compile)
    compile_selected_tests
    ;;
  list)
    printf '%s\n' "${TESTS[@]}"
    ;;
  podman-compile)
    run_podman "scripts/test-network-compat.sh compile"
    ;;
  kernel)
    run_podman "scripts/test-network-compat.sh compile && make kernel"
    ;;
  flask-demo)
    run_podman "scripts/test-network-compat.sh compile && make run_kernel BENCHMARK=flask_socket_demo"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
