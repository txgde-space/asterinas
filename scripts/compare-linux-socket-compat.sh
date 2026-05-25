#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMON_TEST="test/initramfs/src/regression/network/linux_socket_compat_common.c"
REGRESSION_RUNNER="test/initramfs/src/regression/scripts/run_regression_test.sh"
UBUNTU_IMAGE="${UBUNTU_IMAGE:-docker.io/library/ubuntu:24.04}"
ASTERINAS_IMAGE="${ASTERINAS_IMAGE:-docker.io/asterinas/asterinas:0.18.0-20260603}"
ORIGINAL_REF="${ORIGINAL_REF:-old-origin/main}"
MODE="${1:-all}"
LOG_DIR="${LOG_DIR:-${ROOT_DIR}/target/linux-socket-compat-compare}"
RESULT_FILE="${LOG_DIR}/summary.tsv"

usage() {
  cat <<EOF
Usage:
  scripts/compare-linux-socket-compat.sh [all|ubuntu|current|original]

Environment:
  ORIGINAL_REF       Git ref used as the pre-fix Asterinas baseline. Default: old-origin/main
  UBUNTU_IMAGE       Linux baseline image. Default: docker.io/library/ubuntu:24.04
  ASTERINAS_IMAGE    Asterinas build image. Default: docker.io/asterinas/asterinas:0.18.0-20260603
  LOG_DIR            Directory for captured logs. Default: target/linux-socket-compat-compare

The script prints summary lines from the same linux_socket_compat_common test
on all targets. Asterinas runs use AUTO_TEST=regression with a temporary runner
that executes only /test/network/linux_socket_compat_common, so the pass/fail
counts are directly comparable with Ubuntu.
EOF
}

log_section() {
  printf '\n========== %s ==========\n' "$1"
}

run_and_capture() {
  local name="$1"
  shift
  local log_file="${LOG_DIR}/${name}.log"
  local passed failed verdict

  mkdir -p "${LOG_DIR}"
  printf 'Log: %s\n' "${log_file}"

  set +e
  "$@" 2>&1 | tee "${log_file}"
  local status=${PIPESTATUS[0]}
  set -e

  printf '\n[%s] exit code: %s\n' "${name}" "${status}"
  if grep -E "linux_socket_compat_common|summary:|tests failed|All regression tests passed|Regression test failed" "${log_file}" >/dev/null 2>&1; then
    printf '[%s] summary lines:\n' "${name}"
    grep -E "linux_socket_compat_common|summary:|tests failed|All regression tests passed|Regression test failed" "${log_file}" || true
  else
    printf '[%s] no summary lines found. Check the full log above.\n' "${name}"
  fi

  passed="$(awk '/summary: [0-9]+ tests passed, [0-9]+ tests failed/ { sum += $3 } END { print sum + 0 }' "${log_file}")"
  failed="$(awk '/summary: [0-9]+ tests passed, [0-9]+ tests failed/ { sum += $6 } END { print sum + 0 }' "${log_file}")"
  if [[ "${status}" -eq 0 && "${failed}" -eq 0 && "${passed}" -gt 0 ]]; then
    verdict="PASS"
  else
    verdict="FAIL"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${name}" "${verdict}" "${status}" "${passed}" "${failed}" "${log_file}" >> "${RESULT_FILE}"

  return "${status}"
}

print_result_table() {
  log_section "Result Table"

  if [[ ! -s "${RESULT_FILE}" ]]; then
    printf 'No result rows were collected.\n'
    return
  fi

  printf '+--------------------+--------+------+--------+--------+--------------------------------------------------------------+\n'
  printf '| Target             | Result | Exit | Passed | Failed | Log                                                          |\n'
  printf '+--------------------+--------+------+--------+--------+--------------------------------------------------------------+\n'
  while IFS=$'\t' read -r name verdict status passed failed log_file; do
    printf '| %-18s | %-6s | %4s | %6s | %6s | %-60s |\n' \
      "${name}" "${verdict}" "${status}" "${passed}" "${failed}" "${log_file}"
  done < "${RESULT_FILE}"
  printf '+--------------------+--------+------+--------+--------+--------------------------------------------------------------+\n'
}

pull_images() {
  log_section "Pull Images"
  sudo podman pull "${UBUNTU_IMAGE}"
  sudo podman pull "${ASTERINAS_IMAGE}"
}

run_ubuntu_baseline() {
  log_section "Ubuntu 24.04 Linux Baseline"
  run_and_capture ubuntu2404 \
    sudo podman run --rm \
      --network=host \
      -v "${ROOT_DIR}:/work:ro" \
      -w /work \
      "${UBUNTU_IMAGE}" \
      bash -lc "apt-get update >/dev/null && apt-get install -y gcc libc6-dev >/dev/null && gcc -Wall -Werror ${COMMON_TEST} -o /tmp/linux_socket_compat_common && /tmp/linux_socket_compat_common"
}

run_current_asterinas() {
  log_section "Current Asterinas"
  local runner="${ROOT_DIR}/${REGRESSION_RUNNER}"
  local backup="${runner}.compare-backup"

  cp "${runner}" "${backup}"
  write_common_only_regression_runner "${runner}"

  set +e
  run_and_capture current-asterinas \
    sudo podman run --rm --privileged \
      --network=host \
      -v /dev:/dev \
      -v "${ROOT_DIR}:/root/asterinas" \
      "${ASTERINAS_IMAGE}" \
      bash -lc "cd /root/asterinas && scripts/test-network-compat.sh compile && make kernel && AUTO_TEST=regression make run_kernel"
  local status=$?
  set -e

  mv "${backup}" "${runner}"
  return "${status}"
}

write_common_only_regression_runner() {
  local runner="$1"

  cat > "${runner}" <<'EOF'
#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

echo "Running linux_socket_compat_common only."
cd /test/network
./linux_socket_compat_common
echo "All regression tests passed."
EOF
  chmod +x "${runner}"
}

prepare_original_tree() {
  local tree="$1"

  git -C "${ROOT_DIR}" worktree add --detach "${tree}" "${ORIGINAL_REF}" >/dev/null
  cp "${ROOT_DIR}/${COMMON_TEST}" "${tree}/${COMMON_TEST}"
  write_common_only_regression_runner "${tree}/${REGRESSION_RUNNER}"
}

run_original_asterinas() {
  log_section "Original Asterinas (${ORIGINAL_REF})"
  local tree
  tree="$(mktemp -d "${TMPDIR:-/tmp}/asterinas-original.XXXXXX")"

  prepare_original_tree "${tree}"
  trap 'git -C "${ROOT_DIR}" worktree remove --force "'"${tree}"'" >/dev/null 2>&1 || true' RETURN

  run_and_capture original-asterinas \
    sudo podman run --rm --privileged \
      --network=host \
      -v /dev:/dev \
      -v "${tree}:/root/asterinas" \
      "${ASTERINAS_IMAGE}" \
      bash -lc "cd /root/asterinas && make kernel && AUTO_TEST=regression make run_kernel"
}

main() {
  mkdir -p "${LOG_DIR}"
  : > "${RESULT_FILE}"

  case "${MODE}" in
    all)
      pull_images
      run_ubuntu_baseline || true
      run_original_asterinas || true
      run_current_asterinas || true
      ;;
    ubuntu)
      sudo podman pull "${UBUNTU_IMAGE}"
      run_ubuntu_baseline
      ;;
    original)
      sudo podman pull "${ASTERINAS_IMAGE}"
      run_original_asterinas
      ;;
    current)
      sudo podman pull "${ASTERINAS_IMAGE}"
      run_current_asterinas
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac

  print_result_table
  log_section "Done"
  printf 'Logs are in: %s\n' "${LOG_DIR}"
}

main
