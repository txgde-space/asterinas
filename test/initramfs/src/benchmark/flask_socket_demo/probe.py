#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

import json
import sys
import time
import urllib.error
import urllib.request


def request_json(url, timeout=2.0):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = response.read()
        return response.status, payload


def wait_until_ready(base_url, deadline=10.0):
    end = time.time() + deadline
    last_error = None
    while time.time() < end:
        try:
            status, payload = request_json(base_url + "/health", timeout=1.0)
            if status == 200 and b"ok" in payload:
                return
        except OSError as err:
            last_error = err
        time.sleep(0.2)
    raise RuntimeError(f"{base_url} did not become ready: {last_error}")


def check(condition, name):
    if not condition:
        raise RuntimeError(name)
    print(f"flask_socket_demo: PASS {name}", flush=True)


def main():
    if len(sys.argv) < 2:
        print("usage: probe.py <base-url> [<base-url> ...]", file=sys.stderr)
        return 2

    passed = 0
    for base_url in sys.argv[1:]:
        wait_until_ready(base_url)

        status, payload = request_json(base_url + "/api/status")
        data = json.loads(payload.decode())
        check(status == 200 and data["status"] == "ok", f"{base_url} index")
        passed += 1

        status, payload = request_json(base_url + "/echo/linux-socket")
        data = json.loads(payload.decode())
        check(status == 200 and data["echo"] == "linux-socket", f"{base_url} echo")
        passed += 1

        status, payload = request_json(base_url + "/large")
        check(status == 200 and len(payload) == 65536, f"{base_url} large-response")
        passed += 1

        status, payload = request_json(base_url + "/request-info")
        data = json.loads(payload.decode())
        check(status == 200 and data["host"], f"{base_url} request-info")
        passed += 1

    print(f"flask_socket_demo probe summary: {passed} tests passed, 0 tests failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
