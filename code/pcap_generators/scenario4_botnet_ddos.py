#!/usr/bin/env python3
"""
=============================================================================
Network Forensics Project — Scenario 4: Botnet DDoS Attack
=============================================================================
Timeline:
  t=300s:   C2 Check-in (DNS query + TCP connection to port 6667)
  t=400s:   Internal Lateral Propagation (Port scanning of subnet)
  t=600s:   Catastrophic DDoS Assault (50 Mbps UDP flood)
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
DEFAULT_PCAP_PATH    = "pcaps/originals/scenario4_botnet_ddos.pcap"
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
CAPTURE_GRACE_SEC    = 3            
CLOUD_IP             = "10.0.0.254" 
VICTIM_IP            = "192.168.1.100"  # External victim for DDoS attack
C2_DOMAIN            = "c2.botnet.com"  # Malicious C2 domain
C2_PORT              = 6667              # IRC botnet port
UDP_BANDWIDTH        = "4000K"           # Normal camera bandwidth: 500KB/s
DDOS_BANDWIDTH       = "50M"             # Attack bandwidth: 50 Mbps
BEHAVIOURS_DIR        = os.path.join(os.path.dirname(__file__), "iot_behaviours")
MQTT_KEEPALIVE_SCRIPT = os.path.join(BEHAVIOURS_DIR, "mqtt_keepalive.py")
MQTT_TEMP_SCRIPT      = os.path.join(BEHAVIOURS_DIR, "mqtt_temperature.py")
NTP_SYNC_SCRIPT       = os.path.join(BEHAVIOURS_DIR, "ntp_sync.py")
DNS_QUERY_SCRIPT      = os.path.join(BEHAVIOURS_DIR, "dns_query.py")
CAMERA_TLS_SCRIPT     = os.path.join(BEHAVIOURS_DIR, "camera_tls_telemetry.py")
CAMERA_UDP_SCRIPT     = os.path.join(BEHAVIOURS_DIR, "camera_udp_stream.py")
C2_CHECKIN_SCRIPT     = os.path.join(BEHAVIOURS_DIR, "c2_checkin.py")
PORT_SCAN_SCRIPT      = os.path.join(BEHAVIOURS_DIR, "port_scan.py")
DDOS_FLOOD_SCRIPT     = os.path.join(BEHAVIOURS_DIR, "ddos_flood.py")

# Attack timeline parameters
C2_TRIGGER_TIME       = 300    # Compromise at t=300s
LATERAL_TRIGGER_TIME  = 400    # Port scanning starts at t=400s
DDOS_TRIGGER_TIME     = 600    # DDoS flood starts at t=600s


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
    victim     = net.addHost("victim",     ip="192.168.1.100/24", mac="00:00:00:00:00:77") 

    info("*** Creating links\n")
    net.addLink(camera,     gateway)   
    net.addLink(thermostat, gateway)   
    net.addLink(attacker,   gateway)
    net.addLink(cloud,      gateway)
    net.addLink(victim,     gateway)

    info("*** Starting network\n")
    net.start()
    net.pingAll()

    return net, gateway, camera, thermostat, attacker, cloud, victim


# ---------------------------------------------------------------------------
# The Target Servers (Dummy Listeners)
# ---------------------------------------------------------------------------
def start_cloud_listeners(cloud):
    info("*** [cloud] Starting dummy listeners (DNS, NTP, TLS, MQTT)\n")
    
    dns_cmd = (
        f"dnsmasq -k -p {DNS_PORT} --listen-address={CLOUD_IP} "
        f"--address=/api.smartcamera.com/{CLOUD_IP} "
        f"--address=/mqtt.smartthermostat.com/10.0.0.2 "
        f"--address=/{C2_DOMAIN}/{CLOUD_IP} "
        f"> /dev/null 2>&1 &"
    )
    cloud.cmd(dns_cmd)
    cloud.cmd(f"nc -k -l {MQTT_PORT} > /dev/null 2>&1 &")
    cloud.cmd(f"nc -k -l {TLS_PORT} > /dev/null 2>&1 &")
    
    cloud.cmd(f"python3 -c 'import socket, time; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"\", {NTP_PORT})); time.sleep(99999)' &")
    
    # Start TCP listener on C2 port (6667) to receive C2 connections
    cloud.cmd(f"nc -k -l {C2_PORT} > /dev/null 2>&1 &")
    
    # Use bash redirection instead of --logfile
    cloud.cmd(
        f"iperf3 -s -p {CAMERA_PORT} > /tmp/iperf3_server_cloud.log 2>&1 &"
    )

    info("*** [cloud] Waiting 2 seconds for servers to bind to ports...\n")
    time.sleep(2)


def start_victim_listeners(victim):
    """Start UDP listener on victim to receive DDoS traffic"""
    info("*** [victim] Starting UDP listener on port 53 (DNS) to receive DDoS traffic\n")
    victim.cmd(
        f"python3 -c 'import socket, time; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
        f"s.bind((\"0.0.0.0\", {DNS_PORT})); time.sleep(99999)' &"
    )
    

# ---------------------------------------------------------------------------
# Traffic generators
# ---------------------------------------------------------------------------
def start_camera_udp_stream(camera, target_ip: str, duration: int):
    info("*** [camera] Starting UDP video-feed stream\n")
    camera.cmd(
        f"python3 {CAMERA_UDP_SCRIPT} {target_ip} {CAMERA_PORT} {UDP_BANDWIDTH} {duration} "
        f"> /tmp/iperf3_client_camera.log 2>&1 &"
    )

def start_thermostat_keepalive(thermostat, target_ip: str, duration: int):
    info("*** [thermostat] Starting MQTT keep-alive simulation\n")

    thermostat.cmd(
        f"python3 {MQTT_KEEPALIVE_SCRIPT} {target_ip} {MQTT_PORT} {KEEPALIVE_INTERVAL} {duration} "
        f"> /tmp/thermostat_keepalive.log 2>&1 &"
    )

def start_thermostat_temperature_report(thermostat, target_ip: str, duration: int):
    info("*** [thermostat] Starting MQTT temperature report simulation\n")
    thermostat.cmd(
        f"python3 {MQTT_TEMP_SCRIPT} {target_ip} {MQTT_PORT} {TEMPERATURE_INTERVAL} {duration} "
        f"> /tmp/thermostat_temperature.log 2>&1 &"
    )

def start_ntp_sync(node, target_ip: str, duration: int):
    info(f"*** [{node.name}] Starting simulated NTP sync\n")
    node.cmd(
        f"python3 {NTP_SYNC_SCRIPT} {target_ip} {NTP_PORT} {NTP_INTERVAL} {duration} "
        f"> /tmp/{node.name}_ntp_sync.log 2>&1 &"
    )

def start_dns_queries(node, target_ip: str, domain: str, duration: int):
    info(f"*** [{node.name}] Starting simulated DNS queries for {domain}\n")
    node.cmd(
        f"python3 {DNS_QUERY_SCRIPT} {target_ip} {domain} {DNS_PORT} {DNS_INTERVAL} {duration} "
        f"> /tmp/{node.name}_dns_query.log 2>&1 &"
    )

def start_camera_tls_telemetry(camera, target_ip: str, duration: int):
    info(f"*** [camera] Starting simulated TLS telemetry\n")
    camera.cmd(
        f"python3 {CAMERA_TLS_SCRIPT} {target_ip} {TLS_PORT} {TLS_INTERVAL} {duration} "
        f"> /tmp/camera_tls_telemetry.log 2>&1 &"
    )

def attacker_activity(attacker):
    info("*** [attacker] Node is SILENT — no traffic will be generated\n")


# ---------------------------------------------------------------------------
# Attack functions for Scenario 4
# ---------------------------------------------------------------------------
def start_c2_checkin(thermostat, c2_ip: str, duration: int, start_time: int):
    """Start C2 check-in: DNS query + TCP connection at specified time"""
    info(f"*** [thermostat] Scheduling C2 check-in to {c2_ip}:{C2_PORT} at t={start_time}s\n")
    thermostat.cmd(
        f"python3 {C2_CHECKIN_SCRIPT} {c2_ip} {C2_DOMAIN} {C2_PORT} {start_time} {duration - start_time} "
        f"> /tmp/thermostat_c2_checkin.log 2>&1 &"
    )

def start_lateral_propagation(thermostat, duration: int, start_time: int):
    """Start port scanning for lateral propagation at specified time"""
    info(f"*** [thermostat] Scheduling lateral propagation (port scan) at t={start_time}s\n")
    # Scan common ports against all hosts in 10.0.0.0/24 subnet
    ports = "22,80,443,3306,5432,6667,8080,8883"
    thermostat.cmd(
        f"python3 {PORT_SCAN_SCRIPT} 10.0.0.0/24 {ports} {start_time} 200 0.01 "
        f"> /tmp/thermostat_port_scan.log 2>&1 &"
    )

def start_ddos_flood(thermostat, victim_ip: str, duration: int, start_time: int):
    """Start UDP flood DDoS attack at specified time"""
    info(f"*** [thermostat] Scheduling DDoS flood to {victim_ip} at t={start_time}s\n")
    thermostat.cmd(
        f"python3 {DDOS_FLOOD_SCRIPT} {victim_ip} 53 {DDOS_BANDWIDTH} {start_time} {duration - start_time} "
        f"> /tmp/thermostat_ddos_flood.log 2>&1 &"
    )


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
        "net", "10.0.0.0/24", "or", "net", "192.168.1.0/24"
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
    parser = argparse.ArgumentParser(description="Scenario 4 — Botnet DDoS Attack")
    parser.add_argument("--duration", "-d", type=int, default=DEFAULT_DURATION)
    parser.add_argument("--pcap", "-p", type=str, default=DEFAULT_PCAP_PATH)
    return parser.parse_args()

def run_scenario(args):
    setLogLevel("info")
    info("=" * 70 + "\n")
    info(" Scenario 4 — Botnet DDoS Attack\n")
    info("=" * 70 + "\n")
    
    net, gateway, camera, thermostat, attacker, cloud, victim = build_topology()
    tcpdump_proc, pcap_file_obj = launch_tcpdump(args.pcap)
    
    info("\n*** Starting baseline services (cloud listeners)\n")
    start_cloud_listeners(cloud)
    start_victim_listeners(victim)
   
    # Start normal device activity
    info("\n*** Starting normal device activities (camera + thermostat baseline)\n")
    start_dns_queries(camera, CLOUD_IP, "api.smartcamera.com", args.duration)
    start_camera_udp_stream(camera, CLOUD_IP, args.duration)
    start_camera_tls_telemetry(camera, CLOUD_IP, args.duration)
    start_ntp_sync(camera, CLOUD_IP, args.duration)

    thermostat_baseline_duration = min(args.duration, C2_TRIGGER_TIME)
    if thermostat_baseline_duration > 0:
        start_dns_queries(thermostat, CLOUD_IP, "mqtt.smartthermostat.com", thermostat_baseline_duration)
        start_thermostat_keepalive(thermostat, CLOUD_IP, thermostat_baseline_duration)
        start_thermostat_temperature_report(thermostat, CLOUD_IP, thermostat_baseline_duration)
        start_ntp_sync(thermostat, CLOUD_IP, thermostat_baseline_duration)

    # Schedule attack phases
    if args.duration > C2_TRIGGER_TIME:
        start_c2_checkin(thermostat, CLOUD_IP, args.duration, C2_TRIGGER_TIME)
    
    if args.duration > LATERAL_TRIGGER_TIME:
        start_lateral_propagation(thermostat, args.duration, LATERAL_TRIGGER_TIME)
    
    if args.duration > DDOS_TRIGGER_TIME:
        start_ddos_flood(thermostat, VICTIM_IP, args.duration, DDOS_TRIGGER_TIME)

    attacker_activity(attacker)
    
    if args.duration == 0:
        info("\n*** Dropping into interactive CLI (duration=0)\n")
        CLI(net)
    else:
        info(f"\n*** Scenario running for {args.duration} seconds …\n")
        scenario_start = time.monotonic()
        try:
            last_reported = 0
            while True:
                elapsed = int(time.monotonic() - scenario_start)
                remaining = args.duration - elapsed
                if remaining <= 0:
                    break
                sleep_time = min(1, remaining)
                time.sleep(sleep_time)
                if elapsed != last_reported and elapsed % 10 == 0:
                    info(f"    [{elapsed:4d}/{args.duration}s] Scenario 4 running\n")
                    last_reported = elapsed
        except KeyboardInterrupt:
            info("\n*** Interrupted by user\n")
    
    if args.duration > 0:
        info(f"\n*** Grace period: {CAPTURE_GRACE_SEC}s to flush trailing packets\n")
        time.sleep(CAPTURE_GRACE_SEC)

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