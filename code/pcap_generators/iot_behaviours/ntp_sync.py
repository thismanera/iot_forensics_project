#!/usr/bin/env python3
"""
Persistent NTP sync simulator.
"""

import socket
import sys
import time


def parse_args():
    if len(sys.argv) < 2:
        print("Usage: ntp_sync.py TARGET_IP [PORT] [INTERVAL] [DURATION]", file=sys.stderr)
        return None

    target_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 123
    interval = int(sys.argv[3]) if len(sys.argv) > 3 else 600
    duration = int(sys.argv[4]) if len(sys.argv) > 4 else 1200

    return target_ip, port, interval, duration


def main() -> int:
    args = parse_args()
    if args is None:
        return 1

    target_ip, port, interval, duration = args
    start_time = time.time()

    while duration <= 0 or time.time() - start_time < duration:
        loop_start = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b"\x1b" + 47 * b"\x00", (target_ip, port))
            sock.close()
        except Exception:
            pass

        execution_time = time.time() - loop_start
        sleep_time = max(0, interval - execution_time)
        time.sleep(sleep_time)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
