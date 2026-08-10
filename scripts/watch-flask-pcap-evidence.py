#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

import argparse
import ipaddress
import os
import re
import struct
import sys
import threading
import time


REQUEST_PATTERN = re.compile(rb"GET (/api/demo/path-proof\?[^ ]+) HTTP/1\.[01]")
PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": ">",
    b"\xa1\xb2\x3c\x4d": ">",
    b"\xd4\xc3\xb2\xa1": "<",
    b"\x4d\x3c\xb2\xa1": "<",
}


def decode_tcp_packet(packet):
    if len(packet) < 14:
        return None

    ether_type = struct.unpack("!H", packet[12:14])[0]
    network_offset = 14
    if ether_type == 0x8100 and len(packet) >= 18:
        ether_type = struct.unpack("!H", packet[16:18])[0]
        network_offset = 18
    if ether_type != 0x0800 or len(packet) < network_offset + 20:
        return None

    version_and_length = packet[network_offset]
    if version_and_length >> 4 != 4:
        return None
    ip_header_length = (version_and_length & 0x0F) * 4
    if ip_header_length < 20 or packet[network_offset + 9] != 6:
        return None

    transport_offset = network_offset + ip_header_length
    if len(packet) < transport_offset + 20:
        return None
    source_port, destination_port = struct.unpack(
        "!HH", packet[transport_offset : transport_offset + 4]
    )
    tcp_header_length = (packet[transport_offset + 12] >> 4) * 4
    payload_offset = transport_offset + tcp_header_length
    if tcp_header_length < 20 or payload_offset > len(packet):
        return None

    return {
        "destination_address": str(
            ipaddress.IPv4Address(packet[network_offset + 16 : network_offset + 20])
        ),
        "destination_port": destination_port,
        "payload": packet[payload_offset:],
        "source_address": str(
            ipaddress.IPv4Address(packet[network_offset + 12 : network_offset + 16])
        ),
        "source_port": source_port,
    }


def wait_for_header(label, path, stop_event):
    last_state = None
    while not stop_event.is_set():
        try:
            capture = open(path, "rb")
        except FileNotFoundError:
            state = "waiting-for-file"
            if state != last_state:
                print(
                    f"QEMU_PCAP_WATCH source={label} file={path} state={state}",
                    flush=True,
                )
                last_state = state
            stop_event.wait(0.2)
            continue

        header = capture.read(24)
        if len(header) < 24:
            capture.close()
            state = f"waiting-for-header bytes={len(header)}"
            if state != last_state:
                print(
                    f"QEMU_PCAP_WATCH source={label} file={path} state={state}",
                    flush=True,
                )
                last_state = state
            stop_event.wait(0.2)
            continue
        endian = PCAP_MAGICS.get(header[:4])
        if endian is None:
            capture.close()
            raise RuntimeError(f"{path} is not a supported PCAP file")
        return capture, endian
    return None


def watch_capture(label, path, stop_event):
    capture_info = wait_for_header(label, path, stop_event)
    if capture_info is None:
        return
    capture, endian = capture_info
    seen_requests = set()
    print(f"QEMU_PCAP_WATCH source={label} file={path} state=ready", flush=True)

    try:
        while not stop_event.is_set():
            packet_header_offset = capture.tell()
            packet_header = capture.read(16)
            if len(packet_header) < 16:
                capture.seek(packet_header_offset)
                time.sleep(0.1)
                continue

            _, _, included_length, _ = struct.unpack(endian + "IIII", packet_header)
            packet = capture.read(included_length)
            if len(packet) < included_length:
                capture.seek(packet_header_offset)
                time.sleep(0.1)
                continue

            decoded = decode_tcp_packet(packet)
            if decoded is None or decoded["destination_port"] != 8080:
                continue
            request_match = REQUEST_PATTERN.search(decoded["payload"])
            if request_match is None:
                continue

            request_target = request_match.group(1).decode("ascii", errors="replace")
            evidence_key = (label, request_target)
            if evidence_key in seen_requests:
                continue
            seen_requests.add(evidence_key)
            print(
                "QEMU_PCAP_EVIDENCE "
                f"source={label} "
                f"src={decoded['source_address']}:{decoded['source_port']} "
                f"dst={decoded['destination_address']}:{decoded['destination_port']} "
                f'request="GET {request_target}"',
                flush=True,
            )
    finally:
        capture.close()


def main():
    parser = argparse.ArgumentParser(
        description="Prints independent QEMU PCAP evidence for Flask demo requests."
    )
    parser.add_argument("net0_pcap", help="PCAP emitted by QEMU net0")
    parser.add_argument("net1_pcap", help="PCAP emitted by QEMU net1")
    args = parser.parse_args()

    stop_event = threading.Event()
    captures = (("net0/eth0", args.net0_pcap), ("net1/eth1", args.net1_pcap))
    threads = [
        threading.Thread(
            target=watch_capture,
            args=(label, os.path.abspath(path), stop_event),
            daemon=True,
        )
        for label, path in captures
    ]
    for thread in threads:
        thread.start()

    try:
        while all(thread.is_alive() for thread in threads):
            time.sleep(0.25)
    except KeyboardInterrupt:
        stop_event.set()
        print("QEMU_PCAP_WATCH state=stopped", flush=True)
    for thread in threads:
        thread.join(timeout=1.0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
