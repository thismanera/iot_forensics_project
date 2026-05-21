#!/usr/bin/env python3
"""
Persistent camera TLS telemetry simulator.
"""

import socket
import sys
import time


def parse_args():
    if len(sys.argv) < 2:
        print("Usage: camera_tls_telemetry.py TARGET_IP [PORT] [INTERVAL] [DURATION]", file=sys.stderr)
        return None

    target_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    interval = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    duration = int(sys.argv[4]) if len(sys.argv) > 4 else 1200

    return target_ip, port, interval, duration


def main() -> int:
    args = parse_args()
    if args is None:
        return 1

    target_ip, port, interval, duration = args
    start_time = time.time()
    next_send = start_time

    while duration <= 0 or time.time() - start_time < duration:
        now = time.time()
        if now < next_send:
            time.sleep(next_send - now)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, port))
            sock.send(b"\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03")
            sock.close()
        except Exception:
            pass

        next_send += interval

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
