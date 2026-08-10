#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

import argparse
import json
import sys
import time
import urllib.request


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request_bytes(url, timeout=2.0):
    with opener.open(url, timeout=timeout) as response:
        return response.status, response.read()


def wait_until_ready(base_url, deadline=10.0):
    end = time.time() + deadline
    last_error = None
    while time.time() < end:
        try:
            status, payload = request_bytes(base_url + "/health", timeout=1.0)
            if status == 200 and json.loads(payload.decode())["status"] == "ok":
                return
        except (OSError, ValueError) as err:
            last_error = err
        time.sleep(0.2)
    raise RuntimeError(f"{base_url} did not become ready: {last_error}")


def check(condition, name, detail=""):
    if not condition:
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(name + suffix)
    evidence = f" evidence={detail}" if detail else ""
    print(f"flask_socket_demo: PASS {name}{evidence}", flush=True)


def parse_endpoint(specification):
    try:
        base_url, expected_local_address = specification.rsplit("=", 1)
    except ValueError as err:
        raise argparse.ArgumentTypeError(
            "endpoint must use <base-url>=<expected-local-address>"
        ) from err
    return base_url.rstrip("/"), expected_local_address


def probe_endpoint(base_url, expected_local_address):
    wait_until_ready(base_url)
    check(True, f"{base_url} health", "expected=HTTP-200 observed=HTTP-200")

    status, payload = request_bytes(base_url + "/api/status")
    data = json.loads(payload.decode())
    listener = data["listener"]
    implicit_listener = data["implicit_listener"]
    listener_compatible = (
        status == 200
        and data["status"] == "ok"
        and data["bind"]["address"] == "0.0.0.0"
        and listener["address"] == "0.0.0.0"
        and listener["reuse_address"]
        and implicit_listener["address"] == "0.0.0.0"
        and implicit_listener["port"] > 0
        and bool(data["wait_backend"])
    )
    check(
        listener_compatible,
        f"{base_url} wildcard-listener",
        (
            "expected=bind/getsockname-0.0.0.0,reuseaddr-on,implicit-port-nonzero "
            f"observed={json.dumps(data, sort_keys=True)}"
        ),
    )

    status, payload = request_bytes(base_url + "/echo/linux-socket")
    data = json.loads(payload.decode())
    check(
        status == 200 and data["echo"] == "linux-socket",
        f"{base_url} request-response",
        f"expected=linux-socket observed={data.get('echo')}",
    )

    status, payload = request_bytes(base_url + "/large")
    check(
        status == 200 and len(payload) == 65536,
        f"{base_url} 64-kib-response",
        f"expected=65536-bytes observed={len(payload)}-bytes",
    )

    status, payload = request_bytes(base_url + "/request-info")
    data = json.loads(payload.decode())
    local_address_matches = (
        status == 200
        and data["local_address"] == expected_local_address
        and data["local_port"] == listener["port"]
    )
    check(
        local_address_matches,
        f"{base_url} accepted-socket-getsockname",
        (
            f"expected={expected_local_address}:{listener['port']} "
            f"observed={json.dumps(data, sort_keys=True)}"
        ),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-generation", choices=("initial", "restarted"))
    parser.add_argument(
        "endpoints",
        metavar="URL=LOCAL_ADDRESS",
        nargs="+",
        type=parse_endpoint,
    )
    args = parser.parse_args()

    for base_url, expected_local_address in args.endpoints:
        probe_endpoint(base_url, expected_local_address)

        if args.expect_generation:
            _, payload = request_bytes(base_url + "/api/status")
            generation = json.loads(payload.decode())["generation"]
            if generation != args.expect_generation:
                raise RuntimeError(
                    f"{base_url} expected generation {args.expect_generation}, got {generation}"
                )

    passed = len(args.endpoints) * 5
    print(f"flask_socket_demo probe summary: {passed} tests passed, 0 tests failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
