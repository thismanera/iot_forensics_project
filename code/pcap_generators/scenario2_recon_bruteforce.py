#!/usr/bin/env python3
"""
=============================================================================
Network Forensics Project — Scenario 2: Reconnaissance + Brute Force
=============================================================================
"""

import argparse
import sys
import time
import subprocess
import os
import shlex
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
DEFAULT_PCAP_PATH    = "pcaps/originals/scenario2_recon_bruteforce.pcap"
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
UDP_BANDWIDTH        = "4000K"       
BEHAVIOURS_DIR        = os.path.join(os.path.dirname(__file__), "iot_behaviours")
MQTT_KEEPALIVE_SCRIPT = os.path.join(BEHAVIOURS_DIR, "mqtt_keepalive.py")
MQTT_TEMP_SCRIPT      = os.path.join(BEHAVIOURS_DIR, "mqtt_temperature.py")
NTP_SYNC_SCRIPT       = os.path.join(BEHAVIOURS_DIR, "ntp_sync.py")
DNS_QUERY_SCRIPT      = os.path.join(BEHAVIOURS_DIR, "dns_query.py")
CAMERA_TLS_SCRIPT     = os.path.join(BEHAVIOURS_DIR, "camera_tls_telemetry.py")
CAMERA_UDP_SCRIPT     = os.path.join(BEHAVIOURS_DIR, "camera_udp_stream.py")

# Attacker timing and behavior
ATTACKER_IP                 = "10.0.0.3"
SCAN_SUBNET_PREFIX          = "10.0.0."
SCAN_HOST_START             = 1
SCAN_HOST_END               = 254
SCAN_PORT_RANGE             = (1, 1024)
SCAN_DELAY_S                = 0.01
RECON_RESULTS_DELAY_S       = 180
BRUTEFORCE_TARGET_IP        = "10.0.0.1"
BRUTEFORCE_TARGET_PORT      = 443
BRUTEFORCE_DELAY_S          = 0.2
BRUTEFORCE_STOP_BEFORE_END  = 120
CONFIG_INTERVAL_S           = 30


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

# ---------------------------------------------------------------------------
# Attacker traffic generators (Scenario 2 specific)
# ---------------------------------------------------------------------------

def attacker_activity(attacker, duration: int):
    info("*** [attacker] Starting recon → brute-force → post-success flow\n")

    attacker_script = (
        "cat <<'PY' > /tmp/attacker_activity.py\n"
        "import socket\n"
        "import subprocess\n"
        "import time\n"
        "\n"
        f"SUBNET_PREFIX = '{SCAN_SUBNET_PREFIX}'\n"
        f"HOST_START = {SCAN_HOST_START}\n"
        f"HOST_END = {SCAN_HOST_END}\n"
        f"ATTACKER_IP = '{ATTACKER_IP}'\n"
        f"PORT_START = {SCAN_PORT_RANGE[0]}\n"
        f"PORT_END = {SCAN_PORT_RANGE[1]}\n"
        f"SCAN_DELAY = {SCAN_DELAY_S}\n"
        f"RECON_DELAY = {RECON_RESULTS_DELAY_S}\n"
        f"BRUTEFORCE_TARGET_IP = '{BRUTEFORCE_TARGET_IP}'\n"
        f"BRUTEFORCE_TARGET_PORT = {BRUTEFORCE_TARGET_PORT}\n"
        f"BRUTEFORCE_DELAY = {BRUTEFORCE_DELAY_S}\n"
        f"BRUTEFORCE_STOP_BEFORE_END = {BRUTEFORCE_STOP_BEFORE_END}\n"
        f"CONFIG_INTERVAL = {CONFIG_INTERVAL_S}\n"
        f"DURATION = {duration}\n"
        "\n"
        "WORDLIST = [\n"
        "    'password', '123456', 'admin', 'camera', 'letmein',\n"
        "    'qwerty', 'ipcam', '1234', 'pass', 'root',\n"
        "    'admin123', 'camera1', 'security', 'default', 'welcome',\n"
        "    '12345678', 'test', 'live', 'stream', 'login',\n"
        "]\n"
        "\n"
        "def ping(ip):\n"
        "    result = subprocess.run(\n"
        "        ['ping', '-c', '1', '-W', '1', ip],\n"
        "        stdout=subprocess.DEVNULL,\n"
        "        stderr=subprocess.DEVNULL,\n"
        "    )\n"
        "    return result.returncode == 0\n"
        "\n"
        "def host_discovery():\n"
        "    print('--- [attacker] Host discovery started ---')\n"
        "    live_hosts = []\n"
        "    for host in range(HOST_START, HOST_END + 1):\n"
        "        ip = f'{SUBNET_PREFIX}{host}'\n"
        "        if ip == ATTACKER_IP:\n"
        "            continue\n"
        "        if ping(ip):\n"
        "            live_hosts.append(ip)\n"
        "    print(f'--- [attacker] Host discovery complete ({len(live_hosts)} hosts) ---')\n"
        "    print(live_hosts)\n"
        "    return live_hosts\n"
        "\n"
        "def port_scan(targets):\n"
        "    if not targets:\n"
        "        print('--- [attacker] No live hosts found for port scan ---')\n"
        "        return\n"
        "    print('--- [attacker] Port scan started ---')\n"
        "    for ip in targets:\n"
        "        for port in range(PORT_START, PORT_END + 1):\n"
        "            try:\n"
        "                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "                s.settimeout(0.05)\n"
        "                s.connect_ex((ip, port))\n"
        "                s.close()\n"
        "            except Exception:\n"
        "                pass\n"
        "            time.sleep(SCAN_DELAY)\n"
        "    print('--- [attacker] Port scan complete ---')\n"
        "\n"
        "def brute_force_until(stop_time):\n"
        "    print('--- [attacker] Brute-force started ---')\n"
        "    i = 0\n"
        "    while True:\n"
        "        if stop_time and time.time() >= stop_time:\n"
        "            break\n"
        "        base = WORDLIST[i % len(WORDLIST)]\n"
        "        suffix = '' if i < len(WORDLIST) else str(i // len(WORDLIST))\n"
        "        password = base + suffix\n"
        "        try:\n"
        "            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "            s.settimeout(1)\n"
        "            s.connect_ex((BRUTEFORCE_TARGET_IP, BRUTEFORCE_TARGET_PORT))\n"
        "            payload = (\n"
        "                'POST /login HTTP/1.1\\r\\n'\n"
        "                f'Host: {BRUTEFORCE_TARGET_IP}\\r\\n'\n"
        "                f'Authorization: Basic {password}\\r\\n'\n"
        "                'Content-Length: 0\\r\\n\\r\\n'\n"
        "            )\n"
        "            s.send(payload.encode())\n"
        "            s.close()\n"
        "        except Exception:\n"
        "            pass\n"
        "        i += 1\n"
        "        time.sleep(BRUTEFORCE_DELAY)\n"
        "    print('--- [attacker] Brute-force stopped (success) ---')\n"
        "\n"
        "def config_phase_until(stop_time):\n"
        "    print('--- [attacker] Post-success configuration started ---')\n"
        "    while True:\n"
        "        if stop_time and time.time() >= stop_time:\n"
        "            break\n"
        "        try:\n"
        "            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "            s.settimeout(2)\n"
        "            s.connect_ex((BRUTEFORCE_TARGET_IP, BRUTEFORCE_TARGET_PORT))\n"
        "            s.send(b'CONFIG_PING')\n"
        "            s.close()\n"
        "        except Exception:\n"
        "            pass\n"
        "        time.sleep(CONFIG_INTERVAL)\n"
        "    print('--- [attacker] Post-success configuration stopped ---')\n"
        "\n"
        "start_time = time.time()\n"
        "targets = host_discovery()\n"
        "port_scan(targets)\n"
        "\n"
        "if DURATION == 0:\n"
        "    delay = RECON_DELAY\n"
        "else:\n"
        "    latest_start = start_time + DURATION - BRUTEFORCE_STOP_BEFORE_END\n"
        "    remaining = max(0, latest_start - time.time())\n"
        "    delay = min(RECON_DELAY, remaining)\n"
        "\n"
        "print(f'--- [attacker] Waiting {delay}s to analyze results ---')\n"
        "time.sleep(delay)\n"
        "\n"
        "if DURATION == 0:\n"
        "    brute_force_until(None)\n"
        "else:\n"
        "    scenario_end = start_time + DURATION\n"
        "    brute_force_end = max(time.time(), scenario_end - BRUTEFORCE_STOP_BEFORE_END)\n"
        "    brute_force_until(brute_force_end)\n"
        "    if time.time() < scenario_end:\n"
        "        config_phase_until(scenario_end)\n"
        "PY\n"
        "python3 /tmp/attacker_activity.py &\n"
    )

    attacker.cmd(f"bash -c {shlex.quote(attacker_script)} &")


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
        "-s", "0",
        "-w", abs_path,
        "net", "10.0.0.0/24"    
    ]
    
    errlog = f"/tmp/tcpdump_{os.path.basename(pcap_path)}.log"
    
    try:
        el = open(errlog, "wb")
        
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=el)
        time.sleep(1)
        
        if proc.poll() is not None:
            el.close()
            with open(errlog, "r") as f:
                err_details = f.read().strip()
                
            error(f"*** FATAL: tcpdump exited immediately!\n")
            error(f"*** Reason: {err_details}\n")
            return None, None
            
        info(f"*** tcpdump pid={proc.pid} capturing successfully. Stderr log: {errlog}\n")
        return proc, None
        
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
    parser = argparse.ArgumentParser(description="Scenario 2 — Reconnaissance + Brute Force")
    parser.add_argument("--duration", "-d", type=int, default=DEFAULT_DURATION)
    parser.add_argument("--pcap", "-p", type=str, default=DEFAULT_PCAP_PATH)
    return parser.parse_args()

def run_scenario(args):
    setLogLevel("info")
    info("=" * 70 + "\n")
    info(" Scenario 2 — Reconnaissance + Brute Force\n")
    info("=" * 70 + "\n")
    
    net, gateway, camera, thermostat, attacker, cloud = build_topology()
    tcpdump_proc, pcap_file_obj = launch_tcpdump(args.pcap)
    
    info("\n*** Starting traffic generators\n")
    start_cloud_listeners(cloud)
    attacker_activity(attacker, args.duration)
    
    start_dns_queries(thermostat, CLOUD_IP, "mqtt.smartthermostat.com", args.duration)
    start_thermostat_keepalive(thermostat, CLOUD_IP, args.duration)
    start_thermostat_temperature_report(thermostat, CLOUD_IP, args.duration)
    start_ntp_sync(thermostat, CLOUD_IP, args.duration)
    
    start_dns_queries(camera, CLOUD_IP, "api.smartcamera.com", args.duration)
    start_camera_udp_stream(camera, CLOUD_IP, args.duration)
    start_camera_tls_telemetry(camera, CLOUD_IP, args.duration)
    start_ntp_sync(camera, CLOUD_IP, args.duration)

    # ── Attacker traffic is handled in attacker_activity() ───────────────
    
    if args.duration == 0:
        info("\n*** Dropping into interactive CLI (duration=0)\n")
        CLI(net)
    else:
        info(f"\n*** Scenario running for {args.duration} seconds …\n")
        try:
            for elapsed in range(args.duration):
                time.sleep(1)
                if (elapsed + 1) % 10 == 0:
                    info(f"    [{elapsed + 1:4d}/{args.duration}s] Scenario 2 running\n")
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