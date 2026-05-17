#!/usr/bin/env python3
"""
=============================================================================
Network Forensics Project — Scenario 1: The Operational Baseline
=============================================================================
"""

import argparse
import sys
import time
import subprocess
import os
import shutil
import signal  

from mininet.net    import Mininet
from mininet.node   import OVSSwitch, Controller, OVSController
from mininet.link   import TCLink
from mininet.log    import setLogLevel, info, error
from mininet.cli    import CLI
from mininet.clean  import cleanup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_DURATION     = 1200         
DEFAULT_PCAP_PATH    = "pcaps/originals/scenario1_baseline.pcap"
CAMERA_PORT          = 50005        
MQTT_PORT            = 8883         
NTP_PORT             = 123          
DNS_PORT             = 53           
TLS_PORT             = 443          
KEEPALIVE_INTERVAL   = 10           
TEMPERATURE_INTERVAL = 300          
NTP_INTERVAL         = 600          
DNS_INTERVAL         = 60           
TLS_INTERVAL         = 300          
CLOUD_IP             = "10.0.0.254" 
UDP_BANDWIDTH        = "500K"       


# ---------------------------------------------------------------------------
# Topology builder
# ---------------------------------------------------------------------------
def build_topology():
    info("*** Cleaning up any previous Mininet state\n")
    cleanup()

    # Kill any zombie iperf3 servers from previous runs
    subprocess.run("killall -9 iperf3", shell=True, stderr=subprocess.DEVNULL)

    info("*** Creating Mininet network\n")
    net = Mininet(
        controller=OVSController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
    )

    info("*** Adding controller\n")
    net.addController("c0")

    info("*** Adding OVS gateway switch\n")
    gateway = net.addSwitch("s1", cls=OVSSwitch, failMode="standalone")

    info("*** Adding hosts\n")
    camera     = net.addHost("camera",     ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    thermostat = net.addHost("thermostat", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    attacker   = net.addHost("attacker",   ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    cloud      = net.addHost("cloud",      ip="10.0.0.254/24", mac="00:00:00:00:00:FF") 

    info("*** Creating links\n")
    net.addLink(camera,     gateway)   
    net.addLink(thermostat, gateway)   
    net.addLink(attacker,   gateway)
    net.addLink(cloud,      gateway) 

    info("*** Starting network\n")
    net.start()
    net.pingAll()

    return net, gateway, camera, thermostat, attacker, cloud


# ---------------------------------------------------------------------------
# The Target Servers (Dummy Listeners)
# ---------------------------------------------------------------------------
def start_cloud_listeners(cloud):
    info("*** [cloud] Starting dummy listeners (DNS, NTP, TLS, MQTT)\n")
    
    dns_cmd = (
        f"dnsmasq -k -p {DNS_PORT} --listen-address={CLOUD_IP} "
        f"--address=/api.smartcamera.com/{CLOUD_IP} "
        f"--address=/mqtt.smartthermostat.com/10.0.0.2 "
        f"> /dev/null 2>&1 &"
    )
    cloud.cmd(dns_cmd)
    cloud.cmd(f"nc -k -l {MQTT_PORT} > /dev/null 2>&1 &")
    cloud.cmd(f"nc -k -l {TLS_PORT} > /dev/null 2>&1 &")
    
    cloud.cmd(f"python3 -c 'import socket, time; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"\", {NTP_PORT})); time.sleep(99999)' &")
    
    # Use bash redirection instead of --logfile
    cloud.cmd(
        f"iperf3 -s -p {CAMERA_PORT} > /tmp/iperf3_server_cloud.log 2>&1 &"
    )

    info("*** [cloud] Waiting 2 seconds for servers to bind to ports...\n")
    time.sleep(2)
    

# ---------------------------------------------------------------------------
# Traffic generators
# ---------------------------------------------------------------------------
def start_camera_udp_stream(camera, target_ip: str, duration: int):
    info("*** [camera] Starting UDP video-feed stream\n")
    
    safe_duration = 86400 if duration == 0 else duration
    
    camera.cmd(
        f"iperf3 -c {target_ip} -u -p {CAMERA_PORT} "
        f"-b {UDP_BANDWIDTH} -t {safe_duration} "
        f"> /tmp/iperf3_client_camera.log 2>&1 &"
    )

def start_thermostat_keepalive(thermostat, target_ip: str):
    info("*** [thermostat] Starting MQTT keep-alive simulation\n")

    script = (
        f"while true; do "
        f"  python3 -c 'import socket; s = socket.socket(); s.settimeout(3); "
        f"s.connect((\"{target_ip}\", {MQTT_PORT})); s.send(b\"MQTT_PINGREQ\"); s.close()' 2>/dev/null; "
        f"  sleep {KEEPALIVE_INTERVAL}; "
        f"done"
    )
    thermostat.cmd(f"{script} &")

def start_thermostat_temperature_report(thermostat, target_ip: str):
    info("*** [thermostat] Starting MQTT temperature report simulation\n")
    script = (
        f"while true; do "
        f"  python3 -c 'import socket; s = socket.socket(); s.settimeout(3); "
        f"s.connect((\"{target_ip}\", {MQTT_PORT})); s.send(b\"MQTT_PUBLISH: payload=22.5C\"); s.close()' 2>/dev/null; "
        f"  sleep {TEMPERATURE_INTERVAL}; "
        f"done"
    )
    thermostat.cmd(f"{script} &")

def start_ntp_sync(node, target_ip: str):
    info(f"*** [{node.name}] Starting simulated NTP sync\n")
    script = (
        f"while true; do "
        f"  python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
        f"s.sendto(b\"\\x1b\" + 47 * b\"\\x00\", (\"{target_ip}\", {NTP_PORT}))' 2>/dev/null; "
        f"  sleep {NTP_INTERVAL}; "
        f"done"
    )
    node.cmd(f"{script} &")

def start_dns_queries(node, target_ip: str, domain: str):
    info(f"*** [{node.name}] Starting simulated DNS queries for {domain}\n")
    script = (
        f"while true; do "
        f"  dig @{target_ip} -p {DNS_PORT} {domain} +short > /dev/null 2>&1; "
        f"  sleep {DNS_INTERVAL}; "
        f"done"
    )
    node.cmd(f"bash -c '{script}' &")

def start_camera_tls_telemetry(camera, target_ip: str):
    info(f"*** [camera] Starting simulated TLS telemetry\n")
    script = (
        f"while true; do "
        f"  python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        f"s.settimeout(3); s.connect((\"{target_ip}\", {TLS_PORT})); "
        f"s.send(b\"\\x16\\x03\\x01\\x00\\xf1\\x01\\x00\\x00\\xed\\x03\\x03\"); s.close()' 2>/dev/null; "
        f"  sleep {TLS_INTERVAL}; "
        f"done"
    )
    camera.cmd(f"{script} &")

def attacker_activity(attacker):
    info("*** [attacker] Node is SILENT — no traffic will be generated\n")


# ---------------------------------------------------------------------------
# Capture Handling 
# ---------------------------------------------------------------------------
def launch_tcpdump(pcap_path: str):
    abs_path = os.path.abspath(pcap_path)
    os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
    
    info(f"*** Starting forensic network tap → {abs_path}\n")

    cmd = [
        "tcpdump",
        "-Z", "root",           
        "-i", "any",            
        "-U",                   
        "-w", "-",              
        "net", "10.0.0.0/24"    
    ]
    
    errlog = f"/tmp/tcpdump_{os.path.basename(pcap_path)}.log"
    
    try:
        outfile = open(abs_path, "wb")
        el = open(errlog, "wb")
        
        proc = subprocess.Popen(cmd, stdout=outfile, stderr=el)
        time.sleep(1)
        
        if proc.poll() is not None:
            el.close()
            outfile.close()
            with open(errlog, "r") as f:
                err_details = f.read().strip()
                
            error(f"*** FATAL: tcpdump exited immediately!\n")
            error(f"*** Reason: {err_details}\n")
            return None, None
            
        info(f"*** tcpdump pid={proc.pid} capturing successfully. Stderr log: {errlog}\n")
        return proc, outfile
        
    except Exception as e:
        error(f"*** Error starting tcpdump: {e}\n")
        return None, None

def stop_gateway_capture(proc, file_obj, pcap_path):
    # Send SIGINT gracefully, allowing tcpdump to finish writing the file
    if proc and proc.poll() is None:
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    time.sleep(1)

    # Explicitly close the file object to flush the buffer
    if file_obj and not file_obj.closed:
        file_obj.close()

    # Check the actual string path, not the Python file object
    if pcap_path and os.path.exists(pcap_path):
        subprocess.run(f"chmod 666 {pcap_path}", shell=True)
        info(f"*** Capture successfully finalized: {pcap_path} ({os.path.getsize(pcap_path)} bytes)\n")
    else:
        error("*** No capture file found!\n")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Scenario 1 — Operational Baseline")
    parser.add_argument("--duration", "-d", type=int, default=DEFAULT_DURATION)
    parser.add_argument("--pcap", "-p", type=str, default=DEFAULT_PCAP_PATH)
    return parser.parse_args()

def run_scenario(args):
    setLogLevel("info")
    info("=" * 70 + "\n")
    info(" Scenario 1 — Smart-Home Operational Baseline\n")
    info("=" * 70 + "\n")
    
    net, gateway, camera, thermostat, attacker, cloud = build_topology()
    tcpdump_proc, pcap_file_obj = launch_tcpdump(args.pcap)
    
    info("\n*** Starting traffic generators\n")
    start_cloud_listeners(cloud)
    attacker_activity(attacker)
    
    start_dns_queries(thermostat, CLOUD_IP, "mqtt.smartthermostat.com")
    start_thermostat_keepalive(thermostat, CLOUD_IP)
    start_thermostat_temperature_report(thermostat, CLOUD_IP)
    start_ntp_sync(thermostat, CLOUD_IP)
    
    start_dns_queries(camera, CLOUD_IP, "api.smartcamera.com")
    start_camera_udp_stream(camera, CLOUD_IP, args.duration)
    start_camera_tls_telemetry(camera, CLOUD_IP)
    start_ntp_sync(camera, CLOUD_IP)
    
    if args.duration == 0:
        info("\n*** Dropping into interactive CLI (duration=0)\n")
        CLI(net)
    else:
        info(f"\n*** Scenario running for {args.duration} seconds …\n")
        try:
            for elapsed in range(args.duration):
                time.sleep(1)
                if (elapsed + 1) % 10 == 0:
                    info(f"    [{elapsed + 1:4d}/{args.duration}s] Scenario 1 running\n")
        except KeyboardInterrupt:
            info("\n*** Interrupted by user\n")
    
    info("\n*** Stopping scenario\n")
    # Passes the process, the open python file object, and the string path
    stop_gateway_capture(tcpdump_proc, pcap_file_obj, args.pcap)
    net.stop()
    info("=" * 70 + "\n")

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid() != 0:
        print("[ERROR] This script must be run with sudo / as root.")
        sys.exit(1)
    run_scenario(args)