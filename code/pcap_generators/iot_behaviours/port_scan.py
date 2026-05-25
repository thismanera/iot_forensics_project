#!/usr/bin/env python3
"""
Port scanning simulator for lateral propagation.
Generates TCP SYN packets to adjacent IPs in the subnet.
"""

import socket
import sys
import time
import threading


def parse_args():
    if len(sys.argv) < 3:
        print("Usage: port_scan.py TARGET_SUBNET PORTS [START_TIME] [DURATION] [INTERVAL]", file=sys.stderr)
        return None

    target_subnet = sys.argv[1]  # e.g., "10.0.0.0/24"
    ports = sys.argv[2]  # e.g., "80,443,22,3306,6667"
    start_time = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    duration = int(sys.argv[4]) if len(sys.argv) > 4 else 200
    interval = float(sys.argv[5]) if len(sys.argv) > 5 else 0.01

    return target_subnet, ports, start_time, duration, interval


def parse_subnet(subnet):
    """Parse subnet notation and generate IPs (simple implementation)"""
    # For 10.0.0.0/24, generate 10.0.0.1 to 10.0.0.253
    parts = subnet.split('/')
    base = parts[0].split('.')
    
    ips = []
    base_ip = f"{base[0]}.{base[1]}.{base[2]}."
    
    for i in range(1, 254):  # Skip network (.0) and broadcast (.255)
        ips.append(f"{base_ip}{i}")
    
    return ips


def scan_port(target_ip, port, timeout=1):
    """Attempt TCP connection to a port (generates SYN flood-like traffic)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()
    except Exception:
        pass


def main() -> int:
    args = parse_args()
    if args is None:
        return 1

    target_subnet, ports_str, start_time, duration, interval = args
    
    # Parse ports
    ports = [int(p) for p in ports_str.split(',')]
    
    # Parse subnet
    target_ips = parse_subnet(target_subnet)
    
    script_start = time.time()
    
    # Wait until start_time
    while time.time() - script_start < start_time:
        time.sleep(0.1)
    
    # Begin scanning
    scan_start = time.time()
    while time.time() - scan_start < duration:
        for target_ip in target_ips:
            for port in ports:
                # Spawn thread for each port scan attempt to speed up scanning
                threading.Thread(
                    target=scan_port,
                    args=(target_ip, port, 0.5),
                    daemon=True
                ).start()
                time.sleep(interval)
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
