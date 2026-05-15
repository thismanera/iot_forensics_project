#!/usr/bin/env python3
"""
=============================================================================
Network Forensics Project — Scenario 4: Botnet Infection (Outbound DDoS)
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
  • thermostat  : (Baseline) TCP keep-alive every 10 s → gateway:8883
                  (Baseline) Temperature report every 360 s → gateway:8883
                  (Baseline) NTP sync every 600 s → 91.189.91.157:123
                  (Baseline) DNS queries every 60 s → gateway:53
                  (Hijacked) TCP SYN flood → DDOS_TARGET_IP:80
                              starting at DDOS_START_DELAY seconds.
                              Violates ALL MUD profile rules (new IP, new port,
                              massive volume).
  • attacker    : Sends a simulated Mirai-style C2 command to the thermostat
                  (TCP to thermostat:23, mimicking Telnet-based C2 delivery)
                  before the flood begins.

Capture
-------
  tcpdump is launched automatically on ALL interfaces (-i any).
  The pcap file will be written to /tmp/scenario4_botnet_ddos.pcap

Usage
-----
  sudo python3 scenario4_botnet_ddos.py [--duration SECONDS] [--pcap PATH]

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
# Constants — Baseline (mirrors scenarios 1–3)
# ---------------------------------------------------------------------------
DEFAULT_DURATION       = 3600
DEFAULT_PCAP_PATH      = "/tmp/scenario4_botnet_ddos.pcap"
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
# Constants — Botnet / DDoS (Scenario 4 specific)
# ---------------------------------------------------------------------------
# 198.51.100.0/24 is TEST-NET-3 (RFC 5737) — safe for simulation,
# represents an external web server being targeted.
DDOS_TARGET_IP         = "198.51.100.1"  # Simulated external victim web server
DDOS_TARGET_PORT       = 80              # HTTP — typical DDoS target port
DDOS_START_DELAY       = 60             # Seconds of clean baseline before flood starts
DDOS_SYN_DELAY_S       = 0.002          # Seconds between SYN probes (~500/s)
C2_PORT                = 23             # Telnet port — Mirai-style C2 delivery
THERMOSTAT_IP          = "10.0.0.2"     # Thermostat IP (compromised bot node)


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
# Baseline traffic generators (mirrors scenarios 1–3)
# ---------------------------------------------------------------------------

def start_camera_udp_stream(camera, sink_ip: str, duration: int):
    """
    Camera → thermostat : continuous legitimate UDP video stream at ~500 KB/s.
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
    This continues running even after the botnet infection begins — the
    thermostat maintains its legitimate MQTT heartbeat while simultaneously
    flooding the DDoS target, which is itself a forensic anomaly.
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
    Periodic NTP requests (UDP/123) to an external NTP server.
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
# Attacker / Botnet traffic generators (Scenario 4 specific)
# ---------------------------------------------------------------------------

def send_c2_infection_command(attacker, thermostat_ip: str, c2_delay: int):
    """
    Attacker → thermostat:23 : Mirai-style C2 command delivery via Telnet port.

    Simulates the botnet C2 server instructing the already-infected thermostat
    to begin its DDoS flood. In real Mirai infections, the bot receives commands
    via a TCP connection on port 23 (Telnet), which it originally used to spread
    by brute-forcing weak Telnet credentials.

    This single anomalous inbound connection to the thermostat from the attacker
    is a key forensic indicator — it violates the thermostat's MUD profile
    (no inbound connections are expected) and precedes the flood onset.
    """
    info(
        f"*** [attacker] Scheduling Mirai-style C2 command → "
        f"thermostat ({thermostat_ip}:{C2_PORT}) in {c2_delay}s\n"
    )

    c2_script = (
        f"python3 -c \""
        f"import socket, time; "
        f"time.sleep({c2_delay}); "
        f"print('--- [attacker] Sending C2 infection command ---'); "
        f"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        f"s.settimeout(3); "
        f"s.connect_ex(('{thermostat_ip}', {C2_PORT})); "
        f"s.send("
        f"  b'\\xff\\xfb\\x01\\xff\\xfb\\x03'  "  # Telnet IAC WILL ECHO, WILL SGA
        f"  b'ATTACK {DDOS_TARGET_IP} {DDOS_TARGET_PORT} tcp 9999\\n'"
        f"); "
        f"s.close(); "
        f"print('--- [attacker] C2 command sent ---'); "
        f"\""
    )

    attacker.cmd(f"bash -c '{c2_script}' &")


def start_botnet_syn_flood(thermostat, target_ip: str,
                            target_port: int, flood_delay: int):
    """
    Thermostat → DDOS_TARGET_IP:80 : high-volume TCP SYN flood attack.

    Simulates a Mirai-style infected IoT device participating in a botnet DDoS.
    The thermostat opens rapid TCP connections to the victim web server on port 80,
    never completing the handshake — each attempt generates a SYN packet, and
    since the target is unreachable (simulated IP), an immediate RST/timeout
    occurs, but the SYN packets are captured and generate the DDoS signature.

    Forensic indicators in the pcap:
      • Sudden massive spike in thermostat outbound TCP traffic at T+DDOS_START_DELAY
      • All packets destined for a SINGLE external IP never seen in the baseline
      • Destination port 80 — not in the thermostat MUD profile (only 8883/123/53)
      • No corresponding inbound traffic (SYNs go unanswered — victim unreachable)
      • Thermostat's legitimate MQTT keep-alives continue alongside the flood —
        a dual-traffic anomaly indicating background malware co-existing with
        normal device operation
    """
    info(
        f"*** [thermostat] Scheduling Mirai-style SYN flood → "
        f"{target_ip}:{target_port} (starts in {flood_delay}s)\n"
    )

    flood_script = (
        f"python3 -c \""
        f"import socket, time; "
        f"time.sleep({flood_delay}); "
        f"print('--- [thermostat] SYN flood started ---'); "
        f"target_ip = '{target_ip}'; "
        f"target_port = {target_port}; "
        f"delay = {DDOS_SYN_DELAY_S}; "
        f"while True: "
        f"  try: "
        f"    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        f"    s.settimeout(0.05); "
        f"    s.connect_ex((target_ip, target_port)); "
        f"    s.close(); "
        f"  except: pass; "
        f"  time.sleep(delay); "
        f"\""
    )

    thermostat.cmd(f"bash -c '{flood_script}' &")
    info(
        f"    thermostat → {target_ip}:{target_port} "
        f"TCP SYN flood ~{int(1/DDOS_SYN_DELAY_S)} packets/s "
        f"(starts at T+{flood_delay}s)\n"
    )


# ---------------------------------------------------------------------------
# Capture instructions
# ---------------------------------------------------------------------------

TCPDUMP_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         tcpdump CAPTURE — Scenario 4 Botnet Infection (Outbound DDoS)      ║
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
        description="Scenario 4 — Botnet Infection (Outbound DDoS) (Mininet)"
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
    info(" Scenario 4 — Botnet Infection (Outbound DDoS)\n")
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

    # ── Start attacker — botnet C2 and DDoS flood ─────────────────────────
    info("\n*** Starting botnet infection sequence\n")
    info(
        f"    Clean baseline for {DDOS_START_DELAY}s, then C2 command delivered "
        f"and thermostat begins SYN flooding {DDOS_TARGET_IP}:{DDOS_TARGET_PORT}.\n"
    )

    # Attacker delivers the C2 command to the thermostat via Telnet port
    send_c2_infection_command(attacker, THERMOSTAT_IP, DDOS_START_DELAY)

    # Thermostat (now acting as bot) begins the SYN flood
    start_botnet_syn_flood(
        thermostat,
        DDOS_TARGET_IP,
        DDOS_TARGET_PORT,
        DDOS_START_DELAY,
    )

    # ── Run scenario ─────────────────────────────────────────────────────
    if args.duration == 0:
        info("\n*** Dropping into interactive CLI (duration=0)\n")
        info("    Type 'exit' or Ctrl-D to stop the scenario.\n\n")
        CLI(net)
    else:
        info(f"\n*** Scenario running for {args.duration} seconds …\n")
        info(f"    DDoS flood begins at T+{DDOS_START_DELAY}s.\n")
        info("    Press Ctrl-C to stop early.\n\n")
        try:
            for elapsed in range(args.duration):
                time.sleep(1)
                if (elapsed + 1) % 10 == 0:
                    phase = (
                        "BASELINE only"
                        if (elapsed + 1) <= DDOS_START_DELAY
                        else f"BASELINE + SYN FLOOD active → {DDOS_TARGET_IP}:{DDOS_TARGET_PORT}"
                    )
                    info(
                        f"    [{elapsed + 1:4d}/{args.duration}s] "
                        f"Scenario 4 — {phase}\n"
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
    info(f"\n    Scenario 4 capture: {args.pcap}\n")
    info("    Open with: wireshark " + args.pcap + "\n")
    info("=" * 70 + "\n")


if __name__ == "__main__":
    args = parse_args()

    import os
    if os.geteuid() != 0:
        print("[ERROR] This script must be run with sudo / as root.")
        sys.exit(1)

    run_scenario(args)
