#!/usr/bin/env python3
"""
Persistent camera UDP stream launcher (paced UDP sender).
"""

import socket
import sys
import time


def parse_args():
    if len(sys.argv) < 2:
        print("Usage: camera_udp_stream.py TARGET_IP [PORT] [BANDWIDTH] [DURATION]", file=sys.stderr)
        return None

    target_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 50005
    bandwidth = sys.argv[3] if len(sys.argv) > 3 else "500K"
    duration = int(sys.argv[4]) if len(sys.argv) > 4 else 1200

    return target_ip, port, bandwidth, duration


def parse_kbit_rate(rate: str) -> int:
    value = rate.strip().lower()
    if value.endswith("k"):
        return int(float(value[:-1]) * 1000)
    if value.endswith("m"):
        return int(float(value[:-1]) * 1000 * 1000)
    return int(float(value))


def main() -> int:
    args = parse_args()
    if args is None:
        return 1

    target_ip, port, bandwidth, duration = args
    safe_duration = 86400 if duration == 0 else duration

    rate_bps = parse_kbit_rate(bandwidth)
    payload_size = 1200
    payload = b"V" * payload_size
    bytes_per_sec = rate_bps / 8.0
    target_pps = max(1, int(bytes_per_sec / payload_size))
    interval = 1.0 / target_pps

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start_time = time.time()
    next_send = start_time

    while time.time() - start_time < safe_duration:
        now = time.time()
        if now < next_send:
            time.sleep(next_send - now)
        try:
            sock.sendto(payload, (target_ip, port))
        except Exception:
            pass
        next_send += interval

    sock.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
