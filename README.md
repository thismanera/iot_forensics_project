# IoT Behavioral Reconstruction via Passive Network Forensics

This repository contains the simulation code, network traffic datasets, and forensic analysis pipelines for researching IoT behavioral reconstruction. By utilizing a simulated smart home zero-trust architecture, this project demonstrates how to infer physical device states and detect sophisticated cyberattacks purely through the passive analysis of encrypted network flow metadata.

## Project Overview

Modern IoT environments heavily rely on encryption (TLS/DTLS), rendering traditional Deep Packet Inspection (DPI) obsolete. Furthermore, the physical volatility of IoT hardware makes "dead-box" device forensics unreliable. 

This project bridges that semantic gap. It utilizes **Zeek** to extract contextual metadata (Flow Density, Inter-Arrival Times, TCP State distributions, and DNS anomalies) from raw `.pcap` files generated in a **Mininet** virtual environment. By establishing strict Manufacturer Usage Description (MUD) baselines, the forensic pipeline successfully identifies structural anomalies across four escalating adversarial scenarios.

---

## Cryptographic Chain of Custody

To ensure absolute data fidelity and admissibility, a strict chain of custody was maintained. The table below confirms zero data degradation between the original Mininet captures and the working copies analyzed via Zeek.

| Experimental Phase | Evidence File (PCAP/Archive) | SHA-256 Cryptographic Hash | Integrity |
| :--- | :--- | :--- | :---: |
| **Scenario 1: Baseline** | `originals/scenario1_baseline.pcap` <br> `working_copies/scenario1_working_copy.pcap` | `d6bf23c441bb69c46f89c87bb7e2f457baf4cac4f910372332722b228bd12936` <br> `d6bf23c441bb69c46f89c87bb7e2f457baf4cac4f910372332722b228bd12936` | ✅ Verified |
| **Scenario 2: Recon & Brute-Force** | `originals/scenario2_recon_bruteforce.pcap` <br> `working_copies/scenario2_working_copy.pcap` | `a94fcc7c7ef145fcdbb1bc4f70134005703ca5cd38b3b440969f67ea03abd094` <br> `a94fcc7c7ef145fcdbb1bc4f70134005703ca5cd38b3b440969f67ea03abd094` | ✅ Verified |
| **Scenario 3: Exfiltration** | `originals/scenario3_exfiltration.pcap` <br> `working_copies/scenario3_working_copy.pcap` | `c3fd72fa20c38d241cb089c866a5e27a24fe264f0a1d04a208de53c3d35b0c17` <br> `c3fd72fa20c38d241cb089c866a5e27a24fe264f0a1d04a208de53c3d35b0c17` | ✅ Verified |
| **Scenario 4: Botnet DDoS** | `originals/scenario4_botnet.pcap` <br> `working_copies/scenario4_working_copy.pcap` | `0be2d975155a51dbbab00fb96301bb66d30fed5138694c5abfd7d6c3dec9de70` <br> `0be2d975155a51dbbab00fb96301bb66d30fed5138694c5abfd7d6c3dec9de70` | ✅ Verified |
| **Compressed Archives** | `original_scenarios.tar.xz` <br> `working_scenarios.tar.xz` | `fb0fe531f28d635dd614bd2bb914f4ec87845acb55f6507be17b43f340caafb4` <br> `7cd22d49fb7e893ee4865d4e6a0b39728541b884ea759dc17f4a7b0b0a86ecc5` | ✅ Verified |

---

### The Experimental Scenarios

1. **Scenario 1: Operational Baseline:** Establishes the "ground truth" of the smart home. Features a Smart Thermostat generating deterministic MQTT keep-alives (10.00s IAT) and a Smart Camera transmitting a 500 KB/s UDP video stream.
2. **Scenario 2: Reconnaissance & Brute-Force:** An internal attacker performs a massive subnet sweep and TLS credential brute-force, demonstrating how threshold-based TCP connection state tripwires (an exploding `SF`-to-`REJ` ratio) can instantly detect lateral scanning.
3. **Scenario 3: Stealth Data Exfiltration:** A post-exploitation attack where the compromised camera masquerades a hijacked UDP video stream over TCP/443 and alters its DNS polling to a Command & Control (C2) domain, bypassing standard volumetric heuristics.
4. **Scenario 4: Botnet Infection & DDoS:** The thermostat is conscripted via an IRC-style TCP/6667 C2 channel, executes unauthorized lateral scans, and ultimately launches a 7.47 Mbps volumetric UDP DDoS flood against an external target.

---

## Technology Stack

* **Network Emulation:** Mininet, Open vSwitch (OVS)
* **Traffic Capture:** `tcpdump`
* **Forensic Extraction:** Zeek Network Security Monitor
* **Data Analysis:** Python 3, Pandas, Jupyter Notebooks
* **Environment:** Ubuntu 22.04 LTS

---

## Repository Structure

```text
iot_forensics_project/
├── code/
│   ├── pcap_generators/        # Python scripts for Mininet topologies & attacks
│   └── run_all_experiments.sh  # Bash automation for sequential execution
├── pcaps/                      # Raw network traffic captures (evidence)
│   ├── originals/
│   └── working_copies/
├── zeek_logs/                  # Extracted metadata logs (conn.log, dns.log, etc.)
├── notebooks/                  # Jupyter notebooks for Pandas forensic analysis
├── figures/                    # Output charts, heatmaps, and graphs
└── docs/                       # Thesis manuscript and LaTeX source files
```
---

## Getting Started

### 1. Prerequisites

Ensure you have the following installed on your Ubuntu machine:

```bash
sudo apt update
sudo apt install mininet openvswitch-testcontroller tcpdump python3-pip
pip3 install pandas jupyter matplotlib seaborn

```

### 2. Open vSwitch Controller Fix (Ubuntu 20.04+)

Modern Ubuntu repositories replaced the legacy OVS controller. You must symlink the new test controller so Mininet can find it:

```bash
sudo ln -s /usr/bin/ovs-testcontroller /usr/bin/ovs-controller

```

### 3. Running the Simulations

To prevent out-of-memory (OOM) errors and forensic timing distortion (IAT corruption), experiments must be run sequentially.
You can run the automated bash script to execute the entire kill chain:

```bash
chmod +x code/pcap_generators/*
sudo pyhton3 code/pcap_generators/scenarioX.py  
```

The PCAP generators must be executed as sudo since tcpdump requires it to capture traffic.

### 4. Extracting Metadata with Zeek

Ensure Zeek is installed and added to your `$PATH`:

```bash
export PATH=/opt/zeek/bin:$PATH

```

Run Zeek against a generated PCAP to extract the forensic logs:

```bash
zeek -C -r pcaps/scenario4.pcap Log::default_logdir=zeek_logs/scenario4_logs

```

*(The `-C` flag is required to bypass virtualized Mininet checksum offloading errors).*

### 5. Data Analysis

Launch Jupyter to explore the forensic extraction notebooks:

```bash
jupyter notebook

```

Navigate to the `notebooks/` directory and open the analysis files to view the generated interaction heatmaps, TCP state distributions, and throughput graphs.

---
