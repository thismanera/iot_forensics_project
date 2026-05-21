#!/usr/bin/env python3
"""
Persistent DNS query simulator.
"""

import subprocess
import sys
import time


def parse_args():
    if len(sys.argv) < 3:
        print("Usage: dns_query.py TARGET_IP DOMAIN [PORT] [INTERVAL] [DURATION]", file=sys.stderr)
        return None

    target_ip = sys.argv[1]
    domain = sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 53
    interval = int(sys.argv[4]) if len(sys.argv) > 4 else 60
    duration = int(sys.argv[5]) if len(sys.argv) > 5 else 1200

    return target_ip, domain, port, interval, duration


def main() -> int:
    args = parse_args()
    if args is None:
        return 1

    target_ip, domain, port, interval, duration = args
    start_time = time.time()
    next_send = start_time

    while duration <= 0 or time.time() - start_time < duration:
        now = time.time()
        if now < next_send:
            time.sleep(next_send - now)

        try:
            subprocess.run(
                ["dig", f"@{target_ip}", "-p", str(port), domain, "+short"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            pass

        next_send += interval

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
