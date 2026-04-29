#!/usr/bin/env python3
"""Generate synthetic evaluation datasets for the replay harness.

Each dataset is a YAML file with a list of connection events and a paired
ground-truth file that lists which pair_keys should be detected as beacons.

Usage:
    python eval/generate_datasets.py
    # Writes all dataset files into the eval/ directory.
"""

import math
import random
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import yaml

OUTPUT_DIR = Path(__file__).parent
BASE_TIME = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def ts(dt: datetime) -> dict:
    epoch_ns = int(dt.timestamp() * 1_000_000_000)
    utc_str = dt.isoformat().replace("+00:00", "Z")
    return epoch_ns, utc_str


def make_event(src_ip, dst_ip, src_port, dst_port, protocol, dt, packet_size=128, node_id="replay"):
    epoch_ns, utc_str = ts(dt)
    proto_name = "TCP" if protocol == 6 else "UDP"
    return {
        "timestamp_ns": epoch_ns,
        "timestamp_utc": utc_str,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_size": packet_size,
        "protocol": protocol,
        "protocol_name": proto_name,
        "tcp_flags": 0x10 if protocol == 6 else 0,
        "direction": 1,
        "node_id": node_id,
        "connection_key": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto_name}",
    }


def pair_key(src_ip, dst_ip, dst_port, protocol):
    proto_name = "TCP" if protocol == 6 else "UDP"
    return f"{src_ip}->{dst_ip}:{dst_port}/{proto_name}"


# ------------------------------------------------------------------
# Dataset 1: 60-second beacon with low jitter
# ------------------------------------------------------------------

def generate_60s_beacon():
    events = []
    interval_s = 60.0
    jitter_s = 3.0  # ±3s (5% jitter) — realistic for sleepy C2 beacons
    n = 80           # 80 events → ~80 min observation, better FFT resolution
    src, dst, dport, proto = "192.168.1.100", "203.0.113.50", 443, 6

    t = BASE_TIME
    for i in range(n):
        pkt_size = random.randint(118, 138)  # ~128 bytes, low CV
        events.append(make_event(src, dst, 54321, dport, proto, t, pkt_size))
        jitter = random.uniform(-jitter_s, jitter_s)
        t += timedelta(seconds=interval_s + jitter)

    events.sort(key=lambda e: e["timestamp_ns"])
    return events, [pair_key(src, dst, dport, proto)]


# ------------------------------------------------------------------
# Dataset 2: 300-second beacon with moderate jitter (10%)
# ------------------------------------------------------------------

def generate_300s_beacon():
    events = []
    interval_s = 300.0
    jitter_s = 30.0  # ±30s (10% jitter)
    n = 30
    src, dst, dport, proto = "10.0.5.20", "198.51.100.10", 8443, 6

    t = BASE_TIME
    for i in range(n):
        pkt_size = random.randint(200, 250)
        events.append(make_event(src, dst, 61000, dport, proto, t, pkt_size))
        jitter = random.uniform(-jitter_s, jitter_s)
        t += timedelta(seconds=interval_s + jitter)

    events.sort(key=lambda e: e["timestamp_ns"])
    return events, [pair_key(src, dst, dport, proto)]


# ------------------------------------------------------------------
# Dataset 3: NTP traffic — periodic, correctly detected at raw level
# ------------------------------------------------------------------

def generate_ntp_traffic():
    events = []
    # NTP client polls every 64 seconds (RFC 5905 default)
    interval_s = 64.0
    jitter_s = 2.0
    n = 40
    src, dst, dport, proto = "10.0.0.5", "192.0.2.1", 123, 17  # UDP

    t = BASE_TIME
    for i in range(n):
        pkt_size = 48  # NTP packet is exactly 48 bytes
        events.append(make_event(src, dst, 12345, dport, proto, t, pkt_size))
        jitter = random.uniform(-jitter_s, jitter_s)
        t += timedelta(seconds=interval_s + jitter)

    events.sort(key=lambda e: e["timestamp_ns"])
    # Ground truth: NTP IS periodic and the detector correctly identifies it.
    # The replay harness uses benign_baseline_enabled=False to test raw detection
    # accuracy.  Production suppression of NTP (BenignPattern UDP/123) is verified
    # by tests/test_suppression.py::TestStage1Suppression::test_ntp_suppressed_before_fft_scorer.
    return events, [pair_key(src, dst, dport, proto)]


# ------------------------------------------------------------------
# Dataset 4: Mixed — one beacon embedded in benign traffic
# ------------------------------------------------------------------

def generate_mixed():
    events = []
    beacons = []

    # Beacon: 120s interval, consistent 512-byte payloads
    b_src, b_dst, b_dport, b_proto = "10.10.1.50", "203.0.113.99", 80, 6
    t = BASE_TIME
    for i in range(35):
        pkt_size = random.randint(505, 520)
        events.append(make_event(b_src, b_dst, 55000, b_dport, b_proto, t, pkt_size))
        t += timedelta(seconds=120 + random.uniform(-3, 3))
    beacons.append(pair_key(b_src, b_dst, b_dport, b_proto))

    # Benign: random HTTP browsing (highly irregular intervals)
    h_src, h_dst, h_dport, h_proto = "10.10.1.50", "93.184.216.34", 443, 6
    t = BASE_TIME
    for i in range(25):
        pkt_size = random.randint(300, 1400)
        events.append(make_event(h_src, h_dst, random.randint(49152, 65535), h_dport, h_proto, t, pkt_size))
        t += timedelta(seconds=random.uniform(5, 600))

    # NTP: genuinely periodic at ~64s; benign_baseline_enabled=False in replay
    # mode so the detector sees it as-is.  The improved consistency scorer
    # correctly flags it as periodic — include it in ground truth here.
    # Production suppression of NTP is tested in tests/test_suppression.py.
    n_src, n_dst, n_dport, n_proto = "10.10.1.1", "192.0.2.1", 123, 17
    t = BASE_TIME
    for i in range(40):
        events.append(make_event(n_src, n_dst, 12345, n_dport, n_proto, t, 48))
        t += timedelta(seconds=64 + random.uniform(-1, 1))
    beacons.append(pair_key(n_src, n_dst, n_dport, n_proto))

    events.sort(key=lambda e: e["timestamp_ns"])
    return events, beacons


# ------------------------------------------------------------------
# Dataset 5: Random traffic — nothing should be detected
# ------------------------------------------------------------------

def generate_random_traffic():
    events = []
    pairs = [
        ("172.16.0.10", "8.8.8.8",       443, 6),
        ("172.16.0.11", "1.1.1.1",        443, 6),
        ("172.16.0.12", "93.184.216.34",  80,  6),
    ]
    for src, dst, dport, proto in pairs:
        t = BASE_TIME
        for i in range(20):
            pkt_size = random.randint(200, 1400)
            events.append(make_event(src, dst, random.randint(49152, 65535), dport, proto, t, pkt_size))
            t += timedelta(seconds=random.uniform(5, 900))

    events.sort(key=lambda e: e["timestamp_ns"])
    return events, []


# ------------------------------------------------------------------
# Writer
# ------------------------------------------------------------------

def write_dataset(name: str, events: list, beacon_pairs: list):
    events_path = OUTPUT_DIR / f"{name}.yaml"
    gt_path = OUTPUT_DIR / f"{name}_gt.yaml"

    with open(events_path, "w") as f:
        yaml.dump({"dataset": name, "events": events}, f, default_flow_style=False, sort_keys=False)

    with open(gt_path, "w") as f:
        yaml.dump({"dataset": name, "beacon_pairs": beacon_pairs}, f, default_flow_style=False)

    print(f"  {events_path.name}  ({len(events)} events, {len(beacon_pairs)} expected beacon(s))")


if __name__ == "__main__":
    random.seed(42)
    print("Generating synthetic evaluation datasets...")

    datasets = [
        ("60s_beacon",   generate_60s_beacon),
        ("300s_beacon",  generate_300s_beacon),
        ("ntp_traffic",  generate_ntp_traffic),
        ("mixed",        generate_mixed),
        ("random_traffic", generate_random_traffic),
    ]

    for name, generator in datasets:
        events, beacons = generator()
        write_dataset(name, events, beacons)

    print(f"\nDatasets written to {OUTPUT_DIR}/")
    print("Run: python replay.py --events eval/<name>.yaml --ground-truth eval/<name>_gt.yaml")
