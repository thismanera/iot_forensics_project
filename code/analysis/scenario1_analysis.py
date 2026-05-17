"""
Scenario 1 — Baseline Forensic Validation
==========================================
This notebook-ready script ingests Zeek conn.log and
dns.log from the 60-minute IoT operational baseline,
validates each theoretical metric (the "ground truth"),
and exports academic-quality figures for LaTeX.

Network Topology:
  Camera      10.0.0.1  (UDP video stream)
  Thermostat  10.0.0.2  (MQTT broker / gateway)
  Attacker    10.0.0.3  (silent — no traffic)
"""

# %% [markdown]
# # Scenario 1 — Baseline Forensic Validation
# ---

# %%
# ──────────────────────────────────────────────
# 0. Imports and Configuration
# ──────────────────────────────────────────────
import os
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns

warnings.filterwarnings("ignore", category=FutureWarning)

# --- Academic-quality plot defaults ----------------------
plt.rcParams.update({
    "figure.dpi":        300,
    "savefig.dpi":       300,
    "savefig.bbox":      "tight",
    "savefig.pad_inches": 0.1,
    "font.family":       "serif",
    "font.size":         11,
    "axes.labelsize":    12,
    "axes.titlesize":    13,
    "axes.titleweight":  "bold",
    "axes.grid":         True,
    "grid.linestyle":    "--",
    "grid.alpha":        0.6,
    "xtick.labelsize":   10,
    "ytick.labelsize":   10,
    "legend.fontsize":   10,
    "figure.facecolor":  "white",
    "axes.facecolor":    "white",
})
sns.set_palette("muted")

# --- Paths -----------------------------------------------
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
LOG_DIR   = os.path.join(
    BASE_DIR, "..", "..", "zeek_outputs", "scenario1_logs"
)
PLOT_DIR  = os.path.join(BASE_DIR, "..", "..", "plots")
os.makedirs(PLOT_DIR, exist_ok=True)

CONN_LOG = os.path.join(LOG_DIR, "conn.log")
DNS_LOG  = os.path.join(LOG_DIR, "dns.log")

# --- Network constants (must match scenario script) ------
CAMERA_IP      = "10.0.0.1"
THERMOSTAT_IP  = "10.0.0.2"
ATTACKER_IP    = "10.0.0.3"
MQTT_PORT      = 8883       # MQTT-over-TLS port
CAMERA_PORT    = 50005      # iperf3 UDP video-feed port
NTP_PORT       = 123
EPH_PORT_LO    = 50000      # Ephemeral port range
EPH_PORT_HI    = 60000

# --- Expected values ("ground truth") --------------------
EXPECTED_KEEPALIVES   = 360   # 3600 s / 10 s
EXPECTED_TELEMETRY    = 10    # 3600 s / 360 s
EXPECTED_NTP_FLOWS    = 6     # Per user specification
EXPECTED_DNS_TOTAL    = 120   # 60 camera + 60 thermostat
EXPECTED_DNS_CAMERA   = 60    # 3600 s / 60 s
EXPECTED_DNS_THERMO   = 60    # 3600 s / 60 s
EXPECTED_ATTACKER     = 0     # Completely silent


# %%
# ──────────────────────────────────────────────
# 1. Zeek TSV Log Parser
# ──────────────────────────────────────────────
def parse_zeek_log(filepath: str) -> pd.DataFrame:
    """
    Parse a standard Zeek TSV log file into a Pandas
    DataFrame.  Handles the commented metadata header,
    extracts column names from '#fields', maps Zeek's
    '-' unset marker to NaN, and converts the 'ts'
    column to Python datetime objects (UTC).

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the .log file.

    Returns
    -------
    pd.DataFrame
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"Zeek log not found: {filepath}"
        )

    # --- Extract column names from the #fields line ------
    columns = None
    with open(filepath, "r") as fh:
        for line in fh:
            if line.startswith("#fields"):
                # First token is '#fields' itself
                columns = line.strip().split("\t")[1:]
                break

    if columns is None:
        raise ValueError(
            f"No #fields header found in {filepath}"
        )

    # --- Read data rows (skip all '#' comment lines) -----
    df = pd.read_csv(
        filepath,
        sep="\t",
        comment="#",
        header=None,
        names=columns,
        na_values=["-", "(empty)"],
        low_memory=False,
    )

    # --- Convert Zeek epoch timestamp → datetime ---------
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(
            df["ts"], unit="s", utc=True
        )

    # --- Coerce numeric port columns ---------------------
    for col in ("id.orig_p", "id.resp_p"):
        if col in df.columns:
            df[col] = pd.to_numeric(
                df[col], errors="coerce"
            )

    # --- Coerce byte / packet count columns --------------
    byte_cols = [
        "orig_bytes", "resp_bytes",
        "orig_pkts",  "resp_pkts",
        "orig_ip_bytes", "resp_ip_bytes",
        "missed_bytes",
    ]
    for col in byte_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(
                df[col], errors="coerce"
            ).fillna(0).astype(np.int64)

    return df


# %%
# ──────────────────────────────────────────────
# 2. Load Zeek Logs
# ──────────────────────────────────────────────
print("=" * 55)
print(" Loading Zeek Logs")
print("=" * 55)

conn = parse_zeek_log(CONN_LOG)
dns  = parse_zeek_log(DNS_LOG)

print(f"  conn.log : {len(conn):>6,} rows  "
      f"({conn['ts'].min()} → {conn['ts'].max()})")
print(f"  dns.log  : {len(dns):>6,} rows  "
      f"({dns['ts'].min()} → {dns['ts'].max()})")
print()


# %%
# ──────────────────────────────────────────────
# 3. Helper: pretty-print a validation result
# ──────────────────────────────────────────────
def validate(label, expected, observed):
    """Print a PASS / FAIL line for one metric."""
    status = "✓ PASS" if observed == expected else "✗ FAIL"
    print(f"  {status}  {label}: "
          f"expected={expected}, observed={observed}")
    return observed == expected


# %% [markdown]
# ## 3.1 — Thermostat MQTT Keep-Alives
# Filter TCP flows **from** 10.0.0.2 **to** port 8883.
# Both keep-alives (small ~12 B payload every 10 s) and
# telemetry reports (larger payload every 360 s) share
# this destination port, so we separate them by payload
# size.  Expected keep-alive count: **360**.

# %%
print("=" * 55)
print(" Objective 1 — Thermostat Keep-Alives")
print("=" * 55)

# All TCP flows from thermostat to MQTT port
thermo_mqtt = conn[
    (conn["id.orig_h"] == THERMOSTAT_IP)
    & (conn["id.resp_p"] == MQTT_PORT)
    & (conn["proto"] == "tcp")
].copy().sort_values("ts").reset_index(drop=True)

print(f"  Total TCP flows to port {MQTT_PORT} "
      f"from {THERMOSTAT_IP}: {len(thermo_mqtt)}")

# Separate keep-alives (small) from telemetry (large)
# by using a byte-size threshold.  The keep-alive sends
# only 'MQTT_PINGREQ' (12 bytes); telemetry sends ~60 B.
if len(thermo_mqtt) > 0:
    size_threshold = thermo_mqtt["orig_bytes"].quantile(
        0.95
    )
    keepalives = thermo_mqtt[
        thermo_mqtt["orig_bytes"] <= size_threshold
    ].copy()
else:
    keepalives = thermo_mqtt.copy()

n_keepalives = len(keepalives)
validate("Keep-alive flows", EXPECTED_KEEPALIVES,
         n_keepalives)

# --- Inter-Arrival Time (IAT) ---------------------------
if n_keepalives > 1:
    iat = (
        keepalives["ts"]
        .diff()
        .dt.total_seconds()
        .dropna()
    )
    iat_mean = iat.mean()
    iat_var  = iat.var()
    print(f"  IAT  μ = {iat_mean:.4f} s  "
          f"(theoretical: 10.0 s)")
    print(f"  IAT  σ² = {iat_var:.6f} s²")
else:
    print("  (Insufficient flows to compute IAT)")
print()


# %% [markdown]
# ### Figure 1 — Keep-Alive IAT Distribution

# %%
if n_keepalives > 1:
    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.hist(
        iat, bins=40, edgecolor="white",
        color="#4C72B0", alpha=0.85,
    )
    ax.axvline(
        iat_mean, color="#C44E52", ls="--", lw=1.5,
        label=f"Mean = {iat_mean:.2f} s",
    )
    ax.set_xlabel("Inter-Arrival Time (seconds)")
    ax.set_ylabel("Frequency")
    ax.set_title(
        "Thermostat Keep-Alive Inter-Arrival Time "
        "Distribution"
    )
    ax.legend()
    fig.tight_layout()
    fig.savefig(
        os.path.join(PLOT_DIR,
                     "s1_keepalive_iat.pdf")
    )
    fig.savefig(
        os.path.join(PLOT_DIR,
                     "s1_keepalive_iat.png")
    )
    plt.show()
    print("  → Saved s1_keepalive_iat.pdf/.png")
print()


# %% [markdown]
# ## 3.2 — Thermostat Telemetry Reports
# Larger TCP flows on port 8883 representing periodic
# weather / temperature measurements.
# Expected count: **10** (one every 360 s).

# %%
print("=" * 55)
print(" Objective 2 — Thermostat Telemetry")
print("=" * 55)

if len(thermo_mqtt) > 0:
    telemetry = thermo_mqtt[
        thermo_mqtt["orig_bytes"] > size_threshold
    ]
else:
    telemetry = thermo_mqtt.copy()

n_telemetry = len(telemetry)
validate("Telemetry flows", EXPECTED_TELEMETRY,
         n_telemetry)
print()


# %% [markdown]
# ## 3.3 — Camera UDP Video Stream
# Filter UDP traffic **from** 10.0.0.1 on ephemeral
# ports (50000–60000).  Calculate total bytes and plot
# volumetric throughput over time.

# %%
print("=" * 55)
print(" Objective 3 — Camera Streaming")
print("=" * 55)

camera_udp = conn[
    (conn["id.orig_h"] == CAMERA_IP)
    & (conn["proto"] == "udp")
    & (conn["id.resp_p"] >= EPH_PORT_LO)
    & (conn["id.resp_p"] <= EPH_PORT_HI)
].copy().sort_values("ts").reset_index(drop=True)

total_bytes = camera_udp["orig_bytes"].sum()
total_mb    = total_bytes / (1024 ** 2)

print(f"  Camera UDP flows found: {len(camera_udp)}")
print(f"  Total bytes transferred: "
      f"{total_bytes:,} ({total_mb:.2f} MiB)")
print()


# %% [markdown]
# ### Figure 2 — Camera Volumetric Flow Over Time

# %%
if not camera_udp.empty:
    cam = camera_udp.set_index("ts").copy()
    # Resample to 1-minute buckets
    vol = (
        cam["orig_bytes"]
        .resample("1min")
        .sum()
        .fillna(0)
        / (1024 ** 2)
    )

    fig, ax = plt.subplots(figsize=(8, 3.5))
    ax.fill_between(
        vol.index, vol.values,
        alpha=0.35, color="#4C72B0",
    )
    ax.plot(
        vol.index, vol.values,
        color="#4C72B0", lw=1.5,
    )
    ax.set_xlabel("Time")
    ax.set_ylabel("Volume (MiB / minute)")
    ax.set_title(
        "Camera UDP Stream — Volumetric Flow"
    )
    ax.xaxis.set_major_formatter(
        mdates.DateFormatter("%H:%M")
    )
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(
        os.path.join(PLOT_DIR,
                     "s1_camera_volume.pdf")
    )
    fig.savefig(
        os.path.join(PLOT_DIR,
                     "s1_camera_volume.png")
    )
    plt.show()
    print("  → Saved s1_camera_volume.pdf/.png")
else:
    print("  (No camera UDP flows — skipping plot)")
print()


# %% [markdown]
# ## 3.4 — NTP Time Synchronisation
# Both the camera and thermostat send periodic UDP
# packets to port 123.  Expected total: **6**.

# %%
print("=" * 55)
print(" Objective 4 — NTP Flows")
print("=" * 55)

ntp_flows = conn[
    (conn["id.resp_p"] == NTP_PORT)
    & (conn["proto"] == "udp")
]

n_ntp = len(ntp_flows)
validate("NTP flows (UDP/123)", EXPECTED_NTP_FLOWS,
         n_ntp)

if n_ntp > 0:
    ntp_by_src = (
        ntp_flows.groupby("id.orig_h")
        .size()
        .reset_index(name="count")
    )
    print("  Breakdown by source:")
    for _, row in ntp_by_src.iterrows():
        print(f"    {row['id.orig_h']}  →  "
              f"{row['count']} flows")
print()


# %% [markdown]
# ## 3.5 — DNS Queries
# Load `dns.log` and verify 120 total queries
# (60 from Camera, 60 from Thermostat).

# %%
print("=" * 55)
print(" Objective 5 — DNS Queries")
print("=" * 55)

# Filter DNS queries originating from Mininet hosts
dns_mininet = dns[
    dns["id.orig_h"].isin(
        [CAMERA_IP, THERMOSTAT_IP]
    )
]

dns_camera = dns_mininet[
    dns_mininet["id.orig_h"] == CAMERA_IP
]
dns_thermo = dns_mininet[
    dns_mininet["id.orig_h"] == THERMOSTAT_IP
]

n_dns_total  = len(dns_mininet)
n_dns_cam    = len(dns_camera)
n_dns_therm  = len(dns_thermo)

validate("Total DNS queries", EXPECTED_DNS_TOTAL,
         n_dns_total)
validate("  Camera DNS queries", EXPECTED_DNS_CAMERA,
         n_dns_cam)
validate("  Thermostat DNS queries", EXPECTED_DNS_THERMO,
         n_dns_therm)
print()


# %% [markdown]
# ### Figure 3 — DNS Query Timeline

# %%
if n_dns_total > 0:
    fig, ax = plt.subplots(figsize=(8, 3))
    for label, sub, marker, color in [
        ("Camera",     dns_camera, "^", "#4C72B0"),
        ("Thermostat", dns_thermo, "s", "#DD8452"),
    ]:
        if not sub.empty:
            ax.scatter(
                sub["ts"],
                [label] * len(sub),
                marker=marker, s=30,
                color=color, alpha=0.7,
                label=f"{label} ({len(sub)} queries)",
            )
    ax.set_xlabel("Time")
    ax.set_title(
        "DNS Query Timeline by IoT Device"
    )
    ax.legend(loc="upper right")
    ax.xaxis.set_major_formatter(
        mdates.DateFormatter("%H:%M")
    )
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(
        os.path.join(PLOT_DIR,
                     "s1_dns_timeline.pdf")
    )
    fig.savefig(
        os.path.join(PLOT_DIR,
                     "s1_dns_timeline.png")
    )
    plt.show()
    print("  → Saved s1_dns_timeline.pdf/.png")
else:
    print("  (No Mininet DNS queries — skipping plot)")
print()


# %% [markdown]
# ## 3.6 — Attacker Dormancy
# Assert that the attacker node (10.0.0.3) generated
# and received **exactly 0 packets**.

# %%
print("=" * 55)
print(" Objective 6 — Attacker Dormancy")
print("=" * 55)

attacker_flows = conn[
    (conn["id.orig_h"] == ATTACKER_IP)
    | (conn["id.resp_h"] == ATTACKER_IP)
]

n_attacker = len(attacker_flows)
validate("Attacker flows", EXPECTED_ATTACKER,
         n_attacker)

if n_attacker == 0:
    print("  ✓ Attacker node is confirmed dormant.")
else:
    attacker_pkts = (
        attacker_flows["orig_pkts"].sum()
        + attacker_flows["resp_pkts"].sum()
    )
    print(f"  ✗ {n_attacker} flows / "
          f"{attacker_pkts} pkts involving attacker!")
print()


# %% [markdown]
# ## 4 — Composite Summary Figure
# A single multi-panel figure for the thesis showing
# all key traffic patterns at a glance.

# %%
print("=" * 55)
print(" Generating Composite Summary Figure")
print("=" * 55)

fig, axes = plt.subplots(2, 2, figsize=(10, 7))

# Panel (a) — Keep-Alive IAT histogram
ax = axes[0, 0]
if n_keepalives > 1:
    ax.hist(
        iat, bins=40, edgecolor="white",
        color="#4C72B0", alpha=0.85,
    )
    ax.axvline(
        iat_mean, color="#C44E52", ls="--", lw=1.5,
        label=f"μ = {iat_mean:.2f} s",
    )
    ax.legend(fontsize=9)
ax.set_xlabel("IAT (s)")
ax.set_ylabel("Frequency")
ax.set_title("(a) Keep-Alive IAT Distribution")

# Panel (b) — Camera volumetric flow
ax = axes[0, 1]
if not camera_udp.empty:
    ax.fill_between(
        vol.index, vol.values,
        alpha=0.35, color="#4C72B0",
    )
    ax.plot(
        vol.index, vol.values,
        color="#4C72B0", lw=1.2,
    )
    ax.xaxis.set_major_formatter(
        mdates.DateFormatter("%H:%M")
    )
    for lbl in ax.get_xticklabels():
        lbl.set_rotation(30)
        lbl.set_ha("right")
ax.set_xlabel("Time")
ax.set_ylabel("MiB / min")
ax.set_title("(b) Camera UDP Volume")

# Panel (c) — Flow-count bar chart
ax = axes[1, 0]
categories = [
    "Keep-\nAlives",
    "Telemetry",
    "NTP",
    "DNS\n(Camera)",
    "DNS\n(Thermo)",
    "Attacker",
]
observed = [
    n_keepalives, n_telemetry, n_ntp,
    n_dns_cam, n_dns_therm, n_attacker,
]
expected = [
    EXPECTED_KEEPALIVES, EXPECTED_TELEMETRY,
    EXPECTED_NTP_FLOWS, EXPECTED_DNS_CAMERA,
    EXPECTED_DNS_THERMO, EXPECTED_ATTACKER,
]
x = np.arange(len(categories))
w = 0.35
bars_exp = ax.bar(
    x - w / 2, expected, w,
    label="Expected", color="#8DA0CB",
    edgecolor="white",
)
bars_obs = ax.bar(
    x + w / 2, observed, w,
    label="Observed", color="#FC8D62",
    edgecolor="white",
)
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=8)
ax.set_ylabel("Flow Count")
ax.set_title("(c) Expected vs. Observed Flows")
ax.legend(fontsize=9)

# Panel (d) — DNS timeline
ax = axes[1, 1]
if n_dns_total > 0:
    for label, sub, marker, color in [
        ("Camera",     dns_camera, "^", "#4C72B0"),
        ("Thermostat", dns_thermo, "s", "#DD8452"),
    ]:
        if not sub.empty:
            ax.scatter(
                sub["ts"], [label] * len(sub),
                marker=marker, s=20,
                color=color, alpha=0.7,
                label=f"{label} ({len(sub)})",
            )
    ax.legend(fontsize=9, loc="upper right")
    ax.xaxis.set_major_formatter(
        mdates.DateFormatter("%H:%M")
    )
    for lbl in ax.get_xticklabels():
        lbl.set_rotation(30)
        lbl.set_ha("right")
ax.set_xlabel("Time")
ax.set_title("(d) DNS Query Timeline")

fig.suptitle(
    "Scenario 1 — Baseline Traffic Validation",
    fontsize=14, fontweight="bold", y=1.02,
)
fig.tight_layout()
fig.savefig(
    os.path.join(PLOT_DIR, "s1_composite.pdf")
)
fig.savefig(
    os.path.join(PLOT_DIR, "s1_composite.png")
)
plt.show()
print("  → Saved s1_composite.pdf/.png")
print()


# %% [markdown]
# ## 5 — Summary Table

# %%
print("=" * 55)
print(" Validation Summary")
print("=" * 55)

summary = pd.DataFrame({
    "Metric": [
        "Keep-Alive flows",
        "Telemetry flows",
        "Camera UDP flows",
        "NTP flows",
        "DNS total",
        "DNS (Camera)",
        "DNS (Thermostat)",
        "Attacker flows",
    ],
    "Expected": [
        EXPECTED_KEEPALIVES,
        EXPECTED_TELEMETRY,
        "≥ 1",
        EXPECTED_NTP_FLOWS,
        EXPECTED_DNS_TOTAL,
        EXPECTED_DNS_CAMERA,
        EXPECTED_DNS_THERMO,
        EXPECTED_ATTACKER,
    ],
    "Observed": [
        n_keepalives,
        n_telemetry,
        len(camera_udp),
        n_ntp,
        n_dns_total,
        n_dns_cam,
        n_dns_therm,
        n_attacker,
    ],
})

summary["Status"] = summary.apply(
    lambda r: "✓" if str(r["Expected"]) == str(
        r["Observed"]
    ) or (
        str(r["Expected"]).startswith("≥")
        and r["Observed"] >= 1
    ) else "✗",
    axis=1,
)

print(summary.to_string(index=False))
print()
print("All plots saved to:", os.path.abspath(PLOT_DIR))
