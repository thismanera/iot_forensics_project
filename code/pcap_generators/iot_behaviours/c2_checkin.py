#!/usr/bin/env python3
"""
C2 Check-in simulator: DNS query to C2 domain + persistent TCP connection.
Starts at a specific time and maintains the connection.
"""

import subprocess
import socket
import sys
import time
import threading


def parse_args():
    if len(sys.argv) < 4:
        print("Usage: c2_checkin.py TARGET_IP C2_DOMAIN C2_PORT [START_TIME] [DURATION]", file=sys.stderr)
        return None

    target_ip = sys.argv[1]
    c2_domain = sys.argv[2]
    c2_port = int(sys.argv[3])
    start_time = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    duration = int(sys.argv[5]) if len(sys.argv) > 5 else 1200

    return target_ip, c2_domain, c2_port, start_time, duration


def dns_query(target_ip, c2_domain, dns_port=53):
    """Perform DNS query to resolve C2 domain"""
    try:
        subprocess.run(
            ["dig", f"@{target_ip}", "-p", str(dns_port), c2_domain, "+short"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except Exception:
        pass


def maintain_tcp_connection(target_ip, target_port, hold_duration):
    """Establish and hold a TCP connection to C2"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_ip, target_port))
        # Hold connection for the specified duration
        time.sleep(hold_duration)
        sock.close()
    except Exception:
        pass


def main() -> int:
    args = parse_args()
    if args is None:
        return 1

    target_ip, c2_domain, c2_port, start_time, duration = args
    script_start = time.time()

    # Wait until the specified start_time
    while time.time() - script_start < start_time:
        time.sleep(0.1)

    # Perform initial DNS query
    dns_query(target_ip, c2_domain)
    
    # Establish TCP connection and hold it
    remaining_duration = max(0, duration - start_time)
    maintain_tcp_connection(target_ip, c2_port, remaining_duration)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
