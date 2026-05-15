#!/usr/bin/env python3
"""
=============================================================================
Network Forensics Project — Scenario 1: The Operational Baseline
=============================================================================
Topology
--------
  [camera]  ──┐
  [thermostat] ──── [gateway (OVS)] ── (internet / external)
  [attacker]──┘

Behaviour
---------
  • camera      : Continuous UDP stream → gateway:5005
                  (simulates an IP camera video feed, ~500 KB/s)
  • thermostat  : TCP/ping keepalive every 10 s → gateway
                  (simulates an MQTT keep-alive heartbeat)
  • attacker    : Completely silent (no traffic generated)

Capture
-------
  Run the following tcpdump command on the gateway interface to capture
  all baseline traffic to a pcap file:

      sudo tcpdump -i s1-eth1 -w /tmp/scenario1_baseline.pcap -v

  Or capture on ALL switch ports simultaneously:

      sudo tcpdump -i any -w /tmp/scenario1_baseline.pcap \
           not ether host ff:ff:ff:ff:ff:ff 2>/dev/null

  The pcap file will be written to /tmp/scenario1_baseline.pcap inside
  the Mininet VM / Linux host.

Usage
-----
  sudo python3 scenario1_baseline.py [--duration SECONDS] [--pcap PATH]

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
# Constants
# ---------------------------------------------------------------------------
DEFAULT_DURATION   = 120          # seconds the scenario runs before auto-stop
DEFAULT_PCAP_PATH  = "/tmp/scenario1_baseline.pcap"
CAMERA_PORT        = 5005         # UDP destination port (simulated video feed)
MQTT_PORT          = 1883         # TCP port (simulated MQTT keepalive target)
KEEPALIVE_INTERVAL = 10           # seconds between thermostat keepalives
UDP_BANDWIDTH      = "500K"       # iperf3 UDP bandwidth for camera stream


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
        controller=OVSController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
    )

    # -- Controller -----------------------------------------------------------
    info("*** Adding controller\n")
    net.addController("c0")

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
# Traffic generators
# ---------------------------------------------------------------------------

def start_camera_udp_stream(camera, gateway_ip: str, duration: int):
    """
    Camera → gateway : continuous UDP stream using iperf3.
    Simulates a low-bitrate IP camera video feed.

    The gateway acts as the iperf3 server; the camera is the client.
    We start the server on the gateway IP (but since the gateway is a switch
    without an IP in this topology, we use the thermostat as the reflector /
    sink instead — a realistic IoT NVR scenario).
    """
    info("*** [camera] Starting UDP video-feed stream\n")

    # iperf3 server on thermostat (acts as NVR / cloud endpoint)
    # We launch it in the background with & so it doesn't block.
    camera.cmd(
        f"iperf3 -s -u -p {CAMERA_PORT} -1 --daemon "
        f"--logfile /tmp/iperf3_server_camera.log"
    )

    # Small pause to let the server start
    time.sleep(1)

    # iperf3 UDP client — camera streams to thermostat IP as a stand-in NVR
    # (In a real deployment this would be an external NVR/cloud server.)
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
    Thermostat → gateway : a lightweight TCP SYN / ping every KEEPALIVE_INTERVAL s.
    Simulates an MQTT PINGREQ keep-alive packet.

    We use a small Python one-liner loop running inside the host's shell so
    the timing is handled in the background independently of the main process.
    """
    info("*** [thermostat] Starting MQTT keep-alive simulation\n")

    # We send a TCP connect (3-way handshake) then immediately close it, which
    # is representative of an MQTT PINGREQ/PINGRESP exchange at the packet level.
    # Using /dev/tcp bash built-in avoids needing extra tools.
    keepalive_script = (
        f"while true; do "
        f"  python3 -c \""
        f"import socket, time; "
        f"s = socket.socket(); "
        f"s.settimeout(3); "
        f"s.connect(('{gateway_ip}', {MQTT_PORT})); "
        f"s.send(b'MQTT_PINGREQ'); "
        f"s.close()\" 2>/dev/null || "
        # Fallback: plain ICMP ping if TCP connection is refused
        f"  ping -c 1 -W 2 {gateway_ip} > /dev/null 2>&1; "
        f"  sleep {KEEPALIVE_INTERVAL}; "
        f"done"
    )

    thermostat.cmd(f"bash -c '{keepalive_script}' &")
    info(
        f"    thermostat → gateway ({gateway_ip}:{MQTT_PORT}) "
        f"TCP keepalive every {KEEPALIVE_INTERVAL}s\n"
    )


def keep_attacker_silent(attacker):
    """
    Attacker host: no traffic is generated.
    The interface is intentionally left idle to reflect a real forensic
    baseline where the attacker has not yet begun their campaign.
    """
    info("*** [attacker] Node is SILENT — no traffic will be generated\n")
    # Deliberately no commands issued to the attacker host.


# ---------------------------------------------------------------------------
# Capture instructions (printed to stdout for the operator)
# ---------------------------------------------------------------------------

TCPDUMP_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║              tcpdump CAPTURE COMMANDS — Scenario 1 Baseline                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Open a NEW terminal on the Mininet host, then run ONE of the following:    ║
║                                                                              ║
║  ── Option A: Capture on a single gateway port (s1-eth1) ─────────────────  ║
║                                                                              ║
║    sudo tcpdump -i s1-eth1 \\                                                ║
║                 -w {pcap_path} \\                                            ║
║                 -v                                                           ║
║                                                                              ║
║  ── Option B: Capture ALL traffic on every switch port ───────────────────  ║
║                                                                              ║
║    sudo tcpdump -i any \\                                                     ║
║                 -w {pcap_path} \\                                            ║
║                 not ether host ff:ff:ff:ff:ff:ff                             ║
║                                                                              ║
║  ── Option C: Capture from inside Mininet CLI ────────────────────────────  ║
║                                                                              ║
║    mininet> s1 tcpdump -i s1-eth1 -w {pcap_path} &                         ║
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
# Automated in-process tcpdump launch (optional)
# ---------------------------------------------------------------------------

def launch_tcpdump(pcap_path: str, iface: str = "s1-eth1") -> subprocess.Popen:
    """
    Optionally launch tcpdump automatically from within the script.
    Returns the Popen handle so the caller can terminate it later.
    """
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
        time.sleep(1)  # Give tcpdump a moment to open the capture file
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
        description="Scenario 1 — Smart-home Operational Baseline (Mininet)"
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
        help=f"Output path for the baseline pcap file. "
             f"Default: {DEFAULT_PCAP_PATH}",
    )
    parser.add_argument(
        "--auto-capture",
        action="store_true",
        default=False,
        help="Automatically launch tcpdump inside the script (requires root).",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default="s1-eth1",
        help="Switch interface to capture on when --auto-capture is used. "
             "Default: s1-eth1",
    )
    return parser.parse_args()


def run_scenario(args):
    setLogLevel("info")

    info("=" * 70 + "\n")
    info(" Scenario 1 — Smart-Home Operational Baseline\n")
    info("=" * 70 + "\n")

    # Print capture instructions for the operator
    print_capture_instructions(args.pcap)

    # ── Build topology ────────────────────────────────────────────────────
    net, gateway, camera, thermostat, attacker = build_topology(args.pcap)

    # Determine gateway IP.  Because the gateway is an OVS switch it does
    # not have an IP assigned by Mininet.  We use thermostat as the MQTT
    # broker / NVR proxy target (realistic for a home-network scenario).
    # For keep-alive pings we fall back to ICMP → thermostat.
    gateway_ip = "10.0.0.2"   # thermostat acts as broker / NVR endpoint

    # ── Optional: auto-launch tcpdump ────────────────────────────────────
    tcpdump_proc = None
    if args.auto_capture:
        tcpdump_proc = launch_tcpdump(args.pcap, args.iface)

    # ── Start traffic ────────────────────────────────────────────────────
    info("\n*** Starting traffic generators\n")

    keep_attacker_silent(attacker)

    start_thermostat_keepalive(thermostat, gateway_ip, args.duration)

    start_camera_udp_stream(camera, gateway_ip, args.duration)

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
                         f"Scenario 1 running — "
                         f"camera streaming UDP, thermostat keepalive active, "
                         f"attacker silent\n")
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
    info(f"\n    Baseline capture: {args.pcap}\n")
    info("    Open with: wireshark " + args.pcap + "\n")
    info("=" * 70 + "\n")


if __name__ == "__main__":
    args = parse_args()

    # Mininet requires root
    import os
    if os.geteuid() != 0:
        print("[ERROR] This script must be run with sudo / as root.")
        sys.exit(1)

    run_scenario(args)
