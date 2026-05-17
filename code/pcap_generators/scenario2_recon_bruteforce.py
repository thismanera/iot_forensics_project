#!/usr/bin/env python3
"""
=============================================================================
Network Forensics Project — Scenario 2: Reconnaissance and Brute-Force
=============================================================================
Topology
--------
  [camera]  ──┐
  [thermostat] ──── [gateway (OVS)] ── (internet / external)
  [attacker]──┘

Behaviour
---------
  • camera      : Continuous UDP stream → gateway:50005
                  (simulates an IP camera video feed, ~500 KB/s)
                  NTP sync every 600 s (10 min) → 91.189.91.157:123
                  DNS queries every 60 s → gateway:53
                  TLS telemetry every 300 s → 93.184.216.34:443
  • thermostat  : TCP/ping keepalive every 10 s → gateway:8883
                  (simulates a Secure MQTT keep-alive heartbeat)
                  TCP temperature report every 360 s (6 min) → gateway:8883
                  NTP sync every 600 s (10 min) → 91.189.91.157:123
                  DNS queries every 60 s → gateway:53
  • attacker    : Phase 1 — Rapid TCP port scan across all devices
                             (simulates nmap-style SYN scan, ~1000 ports/device)
                  Phase 2 — Concentrated TCP brute-force against camera:443
                             (high-frequency repeated connection attempts)

Capture
-------
  tcpdump is launched automatically on ALL interfaces (-i any).
  The pcap file will be written to /tmp/scenario2_recon_bruteforce.pcap
  inside the Mininet VM / Linux host.

Usage
-----
  sudo python3 scenario2_recon_bruteforce.py [--duration SECONDS] [--pcap PATH]

Requirements
------------
  • Mininet   (http://mininet.org)
  • Open vSwitch (OVS)
  • Python 3.6+
  • iperf3    (for UDP stream)  — install with: sudo apt install iperf3
=============================================================================
"""

import argparse
import sys
import time
import subprocess

from mininet.net    import Mininet
from mininet.node   import OVSSwitch, Controller, OVSController
from mininet.link   import TCLink
from mininet.log    import setLogLevel, info, error
from mininet.cli    import CLI
from mininet.clean  import cleanup


# ---------------------------------------------------------------------------
# Constants — Baseline (mirrors scenario 1)
# ---------------------------------------------------------------------------
DEFAULT_DURATION       = 3600          # Seconds the scenario runs (60 min)
DEFAULT_PCAP_PATH      = "/tmp/scenario2_recon_bruteforce.pcap"
CAMERA_PORT            = 50005         # UDP port — simulated video feed
MQTT_PORT              = 8883          # TCP port — Secure MQTT
NTP_PORT               = 123           # UDP port — NTP time sync
DNS_PORT               = 53            # UDP port — DNS resolution
TLS_PORT               = 443           # TCP port — TLS cloud telemetry / camera auth
KEEPALIVE_INTERVAL     = 10            # Seconds between thermostat MQTT keep-alives
TEMPERATURE_INTERVAL   = 360           # Seconds between thermostat temperature reports
NTP_INTERVAL           = 600           # Seconds between NTP sync requests (10 min)
DNS_INTERVAL           = 60            # Seconds between DNS queries (1 min)
TLS_INTERVAL           = 300           # Seconds between camera TLS telemetry (5 min)
NTP_SERVER             = "91.189.91.157"  # Simulated ntp.ubuntu.com
TLS_CLOUD_SERVER       = "93.184.216.34"  # Simulated api.smartcamera.com
UDP_BANDWIDTH          = "500K"         # iperf3 UDP bandwidth for camera stream

# ---------------------------------------------------------------------------
# Constants — Attacker (Scenario 2 specific)
# ---------------------------------------------------------------------------
SCAN_TARGET_IPS        = ["10.0.0.1", "10.0.0.2"]  # Camera and thermostat
SCAN_PORT_RANGE        = (1, 1024)     # Well-known port range to scan
SCAN_DELAY_S           = 0.005        # Seconds between each probe (200 probes/s)
BRUTEFORCE_TARGET_IP   = "10.0.0.1"   # Camera IP — brute-force target
BRUTEFORCE_TARGET_PORT = 443          # Port — simulated camera web auth
BRUTEFORCE_ATTEMPTS    = 500          # Number of password attempts to simulate
BRUTEFORCE_DELAY_S     = 0.1         # Seconds between brute-force attempts
BRUTEFORCE_START_DELAY = 60          # Seconds after start to begin brute-force
                                      # (gives scan time to finish first)


# ---------------------------------------------------------------------------
# Topology builder
# ---------------------------------------------------------------------------

def build_topology(pcap_path: str):
    """
    Create and return a running Mininet network with the smart-home topology.

    Returns
    -------
    net : Mininet
        The running network object.
    gateway : OVSSwitch
        The central OVS gateway switch.
    camera, thermostat, attacker : Host
        The three IoT / attacker hosts.
    """
    info("*** Cleaning up any previous Mininet state\n")
    cleanup()

    info("*** Creating Mininet network\n")
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
    )

    # -- Switch (gateway) -----------------------------------------------------
    info("*** Adding OVS gateway switch\n")
    gateway = net.addSwitch("s1", cls=OVSSwitch, failMode="standalone")

    # -- Hosts ----------------------------------------------------------------
    info("*** Adding hosts\n")
    camera     = net.addHost("camera",     ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    thermostat = net.addHost("thermostat", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    attacker   = net.addHost("attacker",   ip="10.0.0.3/24", mac="00:00:00:00:00:03")

    # -- Links ----------------------------------------------------------------
    info("*** Creating links\n")
    net.addLink(camera,     gateway)   # s1-eth1
    net.addLink(thermostat, gateway)   # s1-eth2
    net.addLink(attacker,   gateway)   # s1-eth3

    # -- Start network --------------------------------------------------------
    info("*** Starting network\n")
    net.start()

    # Verify basic connectivity (ping all-pairs once)
    info("*** Testing connectivity\n")
    net.pingAll()

    return net, gateway, camera, thermostat, attacker


# ---------------------------------------------------------------------------
# Baseline traffic generators (same as Scenario 1)
# ---------------------------------------------------------------------------

def start_camera_udp_stream(camera, gateway_ip: str, duration: int):
    """
    Camera → gateway : continuous UDP stream using iperf3.
    Simulates a low-bitrate IP camera video feed (~500 KB/s).
    """
    info("*** [camera] Starting UDP video-feed stream\n")

    # iperf3 server on the camera itself (self-loop sink for packet generation)
    camera.cmd(
        f"iperf3 -s -u -p {CAMERA_PORT} -1 --daemon "
        f"--logfile /tmp/iperf3_server_camera.log"
    )
    time.sleep(1)

    thermostat_ip = "10.0.0.2"
    camera.cmd(
        f"iperf3 -c {thermostat_ip} -u -p {CAMERA_PORT} "
        f"-b {UDP_BANDWIDTH} -t {duration} "
        f"--logfile /tmp/iperf3_client_camera.log &"
    )
    info(
        f"    camera → thermostat ({thermostat_ip}:{CAMERA_PORT}) "
        f"UDP {UDP_BANDWIDTH} for {duration}s\n"
    )


def start_thermostat_keepalive(thermostat, gateway_ip: str, duration: int):
    """
    Thermostat → gateway : TCP keep-alive every KEEPALIVE_INTERVAL s.
    Simulates a Secure MQTT PINGREQ heartbeat on port 8883.
    """
    info("*** [thermostat] Starting Secure MQTT keep-alive simulation\n")

    keepalive_script = (
        f"while true; do "
        f"  python3 -c \""
        f"import socket, time; "
        f"s = socket.socket(); "
        f"s.settimeout(3); "
        f"s.connect(('{gateway_ip}', {MQTT_PORT})); "
        f"s.send(b'MQTT_PINGREQ'); "
        f"s.close()\" 2>/dev/null || "
        f"  ping -c 1 -W 2 {gateway_ip} > /dev/null 2>&1; "
        f"  sleep {KEEPALIVE_INTERVAL}; "
        f"done"
    )

    thermostat.cmd(f"bash -c '{keepalive_script}' &")
    info(
        f"    thermostat → gateway ({gateway_ip}:{MQTT_PORT}) "
        f"TCP keep-alive every {KEEPALIVE_INTERVAL}s\n"
    )


def start_thermostat_temperature_report(thermostat, gateway_ip: str, duration: int):
    """
    Thermostat → gateway : simulated MQTT PUBLISH every TEMPERATURE_INTERVAL s.
    Simulates a thermostat sending its current temperature every 6 minutes.
    """
    info("*** [thermostat] Starting MQTT temperature report simulation\n")

    report_script = (
        f"while true; do "
        f"  python3 -c \""
        f"import socket, time; "
        f"s = socket.socket(); "
        f"s.settimeout(3); "
        f"s.connect(('{gateway_ip}', {MQTT_PORT})); "
        f"s.send(b'MQTT_PUBLISH: topic=home/thermostat/temperature payload=22.5C'); "
        f"s.close()\" 2>/dev/null || "
        f"  ping -c 1 -W 2 {gateway_ip} > /dev/null 2>&1; "
        f"  sleep {TEMPERATURE_INTERVAL}; "
        f"done"
    )

    thermostat.cmd(f"bash -c '{report_script}' &")
    info(
        f"    thermostat → gateway ({gateway_ip}:{MQTT_PORT}) "
        f"TCP temperature report every {TEMPERATURE_INTERVAL}s\n"
    )


def start_ntp_sync(node, ntp_server_ip: str):
    """
    Simulates periodic NTP requests from an IoT device to an external NTP server.
    Sends a valid 48-byte NTP client request packet over UDP port 123.
    """
    info(f"*** [{node.name}] Starting simulated NTP sync to {ntp_server_ip}\n")

    ntp_script = (
        f"while true; do "
        f"  python3 -c \""
        f"import socket; "
        f"s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
        f"s.sendto(b'\\x1b' + 47 * b'\\x00', ('{ntp_server_ip}', {NTP_PORT}))\" 2>/dev/null; "
        f"  sleep {NTP_INTERVAL}; "
        f"done"
    )

    node.cmd(f"bash -c '{ntp_script}' &")


def start_camera_dns_queries(camera, gateway_ip: str):
    """
    Camera → Local Gateway : periodic UDP DNS queries on port 53.
    Simulates the camera resolving api.smartcamera.com and stream.smartcamera.com.
    """
    info(f"*** [camera] Starting simulated DNS queries to {gateway_ip}\n")

    dns_query = (
        "b'\\x00\\x01'"
        " + b'\\x01\\x00'"
        " + b'\\x00\\x01'"
        " + b'\\x00\\x00' * 3"
        " + b'\\x03api\\x0csmartcamera\\x03com\\x00'"
        " + b'\\x00\\x01'"
        " + b'\\x00\\x01'"
    )

    dns_script = (
        f"while true; do "
        f"  python3 -c \""
        f"import socket; "
        f"s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
        f"s.sendto({dns_query}, ('{gateway_ip}', {DNS_PORT}))\" 2>/dev/null; "
        f"  sleep {DNS_INTERVAL}; "
        f"done"
    )

    camera.cmd(f"bash -c '{dns_script}' &")
    info(
        f"    camera → gateway ({gateway_ip}:{DNS_PORT}) "
        f"UDP DNS query every {DNS_INTERVAL}s\n"
    )


def start_camera_tls_telemetry(camera, cloud_server_ip: str):
    """
    Camera → Internet : periodic TCP connection on port 443.
    Simulates the camera sending TLS cloud telemetry to api.smartcamera.com.
    """
    info(f"*** [camera] Starting simulated TLS telemetry to {cloud_server_ip}\n")

    tls_script = (
        f"while true; do "
        f"  python3 -c \""
        f"import socket; "
        f"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        f"s.settimeout(3); "
        f"s.connect(('{cloud_server_ip}', {TLS_PORT})); "
        f"s.send(b'\\x16\\x03\\x01\\x00\\xf1\\x01\\x00\\x00\\xed\\x03\\x03'); "
        f"s.close()\" 2>/dev/null; "
        f"  sleep {TLS_INTERVAL}; "
        f"done"
    )

    camera.cmd(f"bash -c '{tls_script}' &")
    info(
        f"    camera → cloud ({cloud_server_ip}:{TLS_PORT}) "
        f"TCP TLS telemetry every {TLS_INTERVAL}s\n"
    )


def start_thermostat_dns_queries(thermostat, gateway_ip: str):
    """
    Thermostat → Local Gateway : periodic UDP DNS queries on port 53.
    Simulates the thermostat resolving mqtt.smartthermostat.com.
    """
    info(f"*** [thermostat] Starting simulated DNS queries to {gateway_ip}\n")

    dns_query = (
        "b'\\x00\\x02'"
        " + b'\\x01\\x00'"
        " + b'\\x00\\x01'"
        " + b'\\x00\\x00' * 3"
        " + b'\\x04mqtt\\x0fsmartThermostat\\x03com\\x00'"
        " + b'\\x00\\x01'"
        " + b'\\x00\\x01'"
    )

    dns_script = (
        f"while true; do "
        f"  python3 -c \""
        f"import socket; "
        f"s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
        f"s.sendto({dns_query}, ('{gateway_ip}', {DNS_PORT}))\" 2>/dev/null; "
        f"  sleep {DNS_INTERVAL}; "
        f"done"
    )

    thermostat.cmd(f"bash -c '{dns_script}' &")
    info(
        f"    thermostat → gateway ({gateway_ip}:{DNS_PORT}) "
        f"UDP DNS query every {DNS_INTERVAL}s\n"
    )


# ---------------------------------------------------------------------------
# Attacker traffic generators (Scenario 2 specific)
# ---------------------------------------------------------------------------

def run_attacker_port_scan(attacker):
    """
    Attacker → all devices : rapid TCP SYN port scan across the well-known
    port range (1–1024) for each target device.

    Simulates a network reconnaissance phase where the attacker maps open
    services on the smart home network. Each port receives a TCP SYN; the
    connection is never completed (the attacker only observes SYN-ACK vs
    RST to determine if a port is open or closed).

    This generates a burst of high-frequency, short-lived TCP connection
    attempts that are easily identifiable in a pcap capture as a port scan.
    """
    info("*** [attacker] Phase 1 — Starting TCP port scan\n")

    targets = " ".join(SCAN_TARGET_IPS)
    port_start, port_end = SCAN_PORT_RANGE

    scan_script = (
        f"python3 -c \""
        f"import socket, time; "
        f"targets = {SCAN_TARGET_IPS}; "
        f"ports = range({port_start}, {port_end + 1}); "
        f"print('--- [attacker] Port scan started ---'); "
        f"for ip in targets: "
        f"  print(f'    Scanning {{ip}} ports {port_start}-{port_end} ...'); "
        f"  for port in ports: "
        f"    try: "
        f"      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        f"      s.settimeout(0.05); "
        f"      s.connect_ex((ip, port)); "
        f"      s.close(); "
        f"    except: pass; "
        f"    time.sleep({SCAN_DELAY_S}); "
        f"print('--- [attacker] Port scan complete ---'); "
        f"\""
    )

    attacker.cmd(f"bash -c '{scan_script}' &")
    info(
        f"    attacker → {SCAN_TARGET_IPS} "
        f"TCP SYN scan ports {port_start}-{port_end} "
        f"(delay={SCAN_DELAY_S}s per probe)\n"
    )


def run_attacker_brute_force(attacker):
    """
    Attacker → camera:443 : concentrated TCP brute-force authentication attack.

    Simulates a password spray / brute-force attack against the camera's web
    interface (port 443). Each attempt opens a TCP connection, sends an HTTP
    Basic Auth header with a different password, then closes. The server
    (camera) will reject each attempt with a TCP RST (since no real service
    is listening), producing a dense cluster of rapid, rejected TCP connections
    in the pcap — the forensic signature of a brute-force attack.

    The attack is launched BRUTEFORCE_START_DELAY seconds after scenario start
    so the port scan traffic and brute-force traffic are temporally separated
    and independently visible in analysis.
    """
    info("*** [attacker] Phase 2 — Scheduling brute-force attack\n")
    info(
        f"    Will start in {BRUTEFORCE_START_DELAY}s: "
        f"{BRUTEFORCE_ATTEMPTS} attempts → "
        f"{BRUTEFORCE_TARGET_IP}:{BRUTEFORCE_TARGET_PORT} "
        f"(delay={BRUTEFORCE_DELAY_S}s per attempt)\n"
    )

    # Wordlist of simulated passwords (realistic subset)
    wordlist = [
        "password", "123456", "admin", "camera", "letmein",
        "qwerty", "ipcam", "1234", "pass", "root",
        "admin123", "camera1", "security", "default", "welcome",
        "12345678", "test", "live", "stream", "login",
    ]

    brute_script = (
        f"python3 -c \""
        f"import socket, time; "
        f"time.sleep({BRUTEFORCE_START_DELAY}); "
        f"wordlist = {wordlist}; "
        f"target_ip = '{BRUTEFORCE_TARGET_IP}'; "
        f"target_port = {BRUTEFORCE_TARGET_PORT}; "
        f"attempts = {BRUTEFORCE_ATTEMPTS}; "
        f"delay = {BRUTEFORCE_DELAY_S}; "
        f"print('--- [attacker] Brute-force started ---'); "
        f"for i in range(attempts): "
        f"  pwd = wordlist[i % len(wordlist)] + str(i // len(wordlist) or ''); "
        f"  try: "
        f"    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        f"    s.settimeout(1); "
        f"    s.connect_ex((target_ip, target_port)); "
        f"    payload = f'POST /login HTTP/1.1\\\\r\\\\nHost: {{target_ip}}\\\\r\\\\n"
        f"Authorization: Basic {{pwd}}\\\\r\\\\nContent-Length: 0\\\\r\\\\n\\\\r\\\\n'; "
        f"    s.send(payload.encode()); "
        f"    s.close(); "
        f"  except: pass; "
        f"  time.sleep(delay); "
        f"print('--- [attacker] Brute-force complete ---'); "
        f"\""
    )

    attacker.cmd(f"bash -c '{brute_script}' &")


# ---------------------------------------------------------------------------
# Capture instructions (printed to stdout for the operator)
# ---------------------------------------------------------------------------

TCPDUMP_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║       tcpdump CAPTURE — Scenario 2 Reconnaissance & Brute-Force            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Capturing ALL traffic on every interface (-i any).                         ║
║                                                                              ║
║  The capture file will be saved to:                                          ║
║    {pcap_path}                                                               ║
║                                                                              ║
║  To open the capture afterwards:                                             ║
║    wireshark {pcap_path}                                                     ║
║    tshark -r {pcap_path} -T fields -e frame.number -e ip.src -e ip.dst      ║
║            -e ip.proto -e frame.len                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


def print_capture_instructions(pcap_path: str):
    print(TCPDUMP_BANNER.format(pcap_path=pcap_path))


# ---------------------------------------------------------------------------
# Automated in-process tcpdump launch
# ---------------------------------------------------------------------------

def launch_tcpdump(pcap_path: str) -> subprocess.Popen:
    """
    Launch tcpdump on all interfaces to capture the full scenario traffic.
    Returns the Popen handle so the caller can terminate it later.
    """
    iface = "any"
    cmd = [
        "tcpdump",
        "-i", iface,
        "-w", pcap_path,
        "--immediate-mode",
    ]
    info(f"*** Launching tcpdump on {iface} → {pcap_path}\n")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)
        return proc
    except FileNotFoundError:
        error("tcpdump not found — install with: sudo apt install tcpdump\n")
        return None
    except PermissionError:
        error("tcpdump requires root privileges. Run the script with sudo.\n")
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Scenario 2 — Reconnaissance and Brute-Force Attack (Mininet)"
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=DEFAULT_DURATION,
        help=f"How long (seconds) to run the scenario before stopping. "
             f"Default: {DEFAULT_DURATION}. Use 0 to drop into interactive CLI.",
    )
    parser.add_argument(
        "--pcap", "-p",
        type=str,
        default=DEFAULT_PCAP_PATH,
        help=f"Output path for the scenario pcap file. "
             f"Default: {DEFAULT_PCAP_PATH}",
    )
    return parser.parse_args()


def run_scenario(args):
    setLogLevel("info")

    info("=" * 70 + "\n")
    info(" Scenario 2 — Reconnaissance and Brute-Force Attack\n")
    info("=" * 70 + "\n")

    # Print capture instructions for the operator
    print_capture_instructions(args.pcap)

    # ── Build topology ────────────────────────────────────────────────────
    net, gateway, camera, thermostat, attacker = build_topology(args.pcap)

    # Thermostat acts as broker / NVR proxy target (realistic for a home network)
    gateway_ip = "10.0.0.2"

    # ── Launch tcpdump on all interfaces ─────────────────────────────────
    tcpdump_proc = launch_tcpdump(args.pcap)

    # ── Start baseline traffic ────────────────────────────────────────────
    info("\n*** Starting baseline traffic generators\n")

    start_thermostat_keepalive(thermostat, gateway_ip, args.duration)
    start_thermostat_temperature_report(thermostat, gateway_ip, args.duration)
    start_thermostat_dns_queries(thermostat, gateway_ip)

    start_camera_udp_stream(camera, gateway_ip, args.duration)
    start_camera_dns_queries(camera, gateway_ip)
    start_camera_tls_telemetry(camera, TLS_CLOUD_SERVER)

    start_ntp_sync(camera, NTP_SERVER)
    start_ntp_sync(thermostat, NTP_SERVER)

    # ── Start attacker traffic ────────────────────────────────────────────
    info("\n*** Starting attacker traffic generators\n")

    run_attacker_port_scan(attacker)
    run_attacker_brute_force(attacker)

    # ── Run scenario ─────────────────────────────────────────────────────
    if args.duration == 0:
        info("\n*** Dropping into interactive CLI (duration=0)\n")
        info("    Type 'exit' or Ctrl-D to stop the scenario.\n\n")
        CLI(net)
    else:
        info(f"\n*** Scenario running for {args.duration} seconds …\n")
        info("    Press Ctrl-C to stop early.\n\n")
        try:
            for elapsed in range(args.duration):
                time.sleep(1)
                if (elapsed + 1) % 10 == 0:
                    info(f"    [{elapsed + 1:4d}/{args.duration}s] "
                         f"Scenario 2 running — "
                         f"baseline active, attacker scanning/bruteforcing\n")
        except KeyboardInterrupt:
            info("\n*** Interrupted by user\n")

    # ── Teardown ─────────────────────────────────────────────────────────
    info("\n*** Stopping scenario\n")

    if tcpdump_proc and tcpdump_proc.poll() is None:
        tcpdump_proc.terminate()
        tcpdump_proc.wait()
        info(f"*** tcpdump stopped — capture saved to {args.pcap}\n")

    net.stop()
    info("*** Network stopped\n")
    info(f"\n    Scenario 2 capture: {args.pcap}\n")
    info("    Open with: wireshark " + args.pcap + "\n")
    info("=" * 70 + "\n")


if __name__ == "__main__":
    args = parse_args()

    import os
    if os.geteuid() != 0:
        print("[ERROR] This script must be run with sudo / as root.")
        sys.exit(1)

    run_scenario(args)
