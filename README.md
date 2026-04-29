# eBPF Beacon Detection System

A network beacon detector. The data plane uses eBPF (XDP for ingress, TC clsact for egress) to capture connection events at low overhead. The control plane runs statistical analysis over per-pair intervals and flags command-and-control (C2) traffic.

Most C2 implants phone home on a schedule. Operators add jitter, sleep cycles, and traffic mimicry, but the underlying regularity usually still survives if you measure intervals carefully. That is what this tool measures.

## Detection signals

Each connection pair gets a combined score from four signals. Weights live in `config.yaml`; the defaults sum to 1.0.

- **Coefficient of variation (35%).** Tight intervals produce low CV. Implants score low, bursty human traffic scores high.
- **FFT periodicity (35%).** A dominant peak in the frequency domain is the single strongest indicator we have.
- **Jitter (15%).** Maximum deviation from the median interval. Catches randomized timing that is still bounded.
- **Packet-size CV (15%).** Implants tend to send near-identical payloads. Browsers do not.

A pair scoring at or above 0.7 generates an alert. Severity follows the score:

| Score   | Severity  | What it usually means                 |
|---------|-----------|---------------------------------------|
| ≥ 0.90  | CRITICAL  | High-confidence beacon, investigate now |
| ≥ 0.80  | HIGH      | Likely beacon                         |
| ≥ 0.70  | MEDIUM    | Suspicious, worth a look              |
| < 0.70  | LOW       | Probably noise                        |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Control Plane                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ Storage  │  │ Detector │  │ Analyzer │  │  Alert Manager   │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
│                         │                                       │
│                    HTTP API (:9090)                             │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Telemetry
┌─────────────────────────────────────────────────────────────────┐
│                         Data Plane                              │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────────┐│
│  │ eBPF Program │──│  Collector   │──│  Telemetry Exporter     ││
│  └──────────────┘  └──────────────┘  └─────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

The data plane lives in the kernel and emits connection events. The control plane is a plain HTTP service that scores them and routes alerts. They talk over `/api/v1/telemetry`, so you can run them on one host or split them across two.

## Quick start

```bash
pip install -r requirements.txt
```

Run the control plane (no root needed):

```bash
python3 -m control_plane.server -c config/config.yaml
```

Run the data plane (eBPF needs root):

```bash
sudo python3 -m data_plane.collector -c ./config/config.yaml
```

Then drive everything from the CLI:

```bash
python3 -m control_plane.cli status              # health, uptime, counters
python3 -m control_plane.cli beacons             # what has been flagged
python3 -m control_plane.cli beacons --min-score 0.8
python3 -m control_plane.cli long-conns          # connections older than 1h
python3 -m control_plane.cli watch               # live view
python3 -m control_plane.cli beacons --csv > beacons.csv
```

## CLI reference

### `status`

Server health, uptime, and the running event counters.

```
    ____                               ____       __            __ 
   / __ )___  ____ __________  ____   / __ \___  / /____  _____/ /_
  / __  / _ \/ __ `/ ___/ __ \/ __ \ / / / / _ \/ __/ _ \/ ___/ __/
 / /_/ /  __/ /_/ / /__/ /_/ / / / // /_/ /  __/ /_/  __/ /__/ /_  
/_____/\___/\__,_/\___/\____/_/ /_//_____/\___/\__/\___/\___/\__/  


═══════════════════════════════════════════════════════════════════
  SYSTEM STATUS
═══════════════════════════════════════════════════════════════════


  ✓ LIVE


  Server:                        localhost:9090
  Status:                        Running
  Uptime:                        2.5h
  Events Received:               15,432
  Connection Pairs:              234
  Beacons Detected:              3
  Alerts Generated:              5
```

### `beacons`

Detected beacons, sorted by score.

```bash
python3 -m control_plane.cli beacons [options]
```

Options:
- `--min-score FLOAT`: minimum beacon score (0.0 to 1.0)
- `--limit INT`: cap the number of results
- `--csv, -o`: emit CSV instead of the table view

Sample output:
```
  SCORE   SEVERITY    SOURCE IP           DEST IP             PORT   PROTO  CONNS     INTERVAL   
  -----   --------    ---------           -------             ----   -----  -----     --------   
  94.2%   CRITICAL    10.0.0.100          203.0.113.50        443    TCP    156       60.0s      
  85.3%   HIGH        10.0.0.101          198.51.100.25       8080   TCP    89        30.0s      
  72.1%   MEDIUM      10.0.0.102          192.0.2.100         53     UDP    45        300.0s     
```

### `long-conns`

Long-lived connections that may indicate persistent C2.

```bash
python3 -m control_plane.cli long-conns [options]
```

Options:
- `--min-duration INT`: minimum duration in seconds (default 3600)
- `--limit INT`: cap the number of results
- `--csv, -o`: emit CSV

### `connections`

All tracked connection pairs.

```bash
python3 -m control_plane.cli connections [options]
```

Options:
- `--limit INT`: cap the number of results
- `--csv, -o`: emit CSV

### `watch`

Live monitoring with auto-refresh.

```bash
python3 -m control_plane.cli watch [options]
```

Options:
- `--interval INT`: refresh interval in seconds (default 5)

`Ctrl+C` exits.

## Talking to a remote control plane

```bash
python3 -m control_plane.cli --host 192.168.1.100 --port 9090 status
python3 -m control_plane.cli --host 192.168.1.100 beacons
python3 -m control_plane.cli --host 192.168.1.100 watch
```

## Configuration

Defaults live in `config/config.yaml`. The interesting knobs:

```yaml
control_plane:
  listen_address: "0.0.0.0"
  listen_port: 9090

detection:
  min_connections: 10      # events required before scoring kicks in
  cv_threshold: 0.15       # tighter than this looks beacon-like
  alert_threshold: 0.7     # combined score that fires alerts
  jitter_threshold: 5.0    # seconds; max acceptable deviation from median
  analysis_interval: 60    # how often we re-score, in seconds

alerting:
  syslog_enabled: true
  file_enabled: true
  file_path: "/var/log/beacon-detect/alerts.json"
  webhook_enabled: false
  webhook_url: ""

whitelist:
  source_ips: []
  destination_ips: []
  destination_ports: [53, 123]   # DNS, NTP
```

The YAML file itself has more options with comments explaining the trade-offs.

## API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check, includes alert-queue backpressure |
| `/api/v1/status` | GET | Server status with drop counters |
| `/api/v1/metrics` | GET | Prometheus text metrics (v0.0.4) |
| `/api/v1/beacons` | GET | Detected beacons |
| `/api/v1/alerts` | GET | Alerts |
| `/api/v1/connections` | GET | Connection pairs |
| `/api/v1/config` | GET/POST | Read or update configuration |
| `/api/v1/telemetry` | POST | Receive telemetry from a data plane |
| `/api/v1/analyze` | POST | Force an analysis run |

### Prometheus metrics

`GET /api/v1/metrics` returns a Prometheus text exposition (Content-Type: `text/plain; version=0.0.4`) with these counters and gauges:

| Metric | Type | Description |
|--------|------|-------------|
| `beacon_detector_events_total` | counter | Connection events received from all data-plane nodes |
| `beacon_detector_pairs_active` | gauge | Connection pairs currently in storage |
| `beacon_detector_analysis_duration_seconds` | gauge | Wall-clock duration of the last analysis run |
| `beacon_detector_alerts_total` | counter | Beacon alerts generated since startup |
| `beacon_detector_buffer_overflow_total` | counter | Events discarded by the data-plane buffer |
| `beacon_detector_ebpf_drops_total` | counter | Events dropped by the eBPF ring buffer |

```bash
curl http://localhost:9090/api/v1/metrics
# HELP beacon_detector_events_total Total connection events received from all data plane nodes.
# TYPE beacon_detector_events_total counter
beacon_detector_events_total 15432
...
```

### Alert queue backpressure

The health endpoint reports queue saturation so a sidecar or orchestrator can shed load before events get dropped silently:

```json
{
  "status": "healthy",
  "alert_queue_fill_percent": 43.0,
  "alert_queue_backpressure": false,
  "alert_queue_drops": 0
}
```

`alert_queue_backpressure` flips to `true` once the queue passes 80% capacity. Drop counters from both the alert queue and the data plane are mirrored at `/api/v1/status`.

## Docker

### Control plane

The control plane is pure Python and runs in a normal container.

```bash
docker compose up control-plane

# Healthy when this returns 200:
curl http://localhost:9090/api/v1/health
```

`docker-compose.yml` also defines a `data-plane-sim` service that fires synthetic 60-second beacon traffic. It is enough to exercise the pipeline end-to-end without eBPF or root. Comment it out in production.

### Data plane

The real data plane will not run inside a normal container. eBPF and XDP attach to a kernel network interface, which means:

| Requirement | Why |
|-------------|-----|
| `--network=host` | XDP and TC hooks live in the host network namespace |
| `--privileged` | `CAP_BPF` and `CAP_NET_ADMIN` are required to load XDP/TC programs |
| Linux ≥ 5.8 | For `BPF_RINGBUF` |
| Kernel headers | BCC compiles the C program at load time |

Either run on the host directly, or use a privileged container:

```bash
sudo docker run --rm \
  --privileged \
  --network=host \
  --pid=host \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v ./config:/app/config:ro \
  beacon-detect-data-plane \
  python3 -m data_plane.collector -c /app/config/config.yaml -i eth0
```

---

## eBPF hook attachment

The collector tries hooks in order of preference so it can see both directions of traffic.

### Preferred: XDP ingress + TC egress

```
NIC RX  ->  xdp_connection_tracker   (direction = INGRESS = 0)
NIC TX  ->  tc_egress_tracker        (direction = EGRESS  = 1)
```

XDP runs before the kernel network stack, which gives the lowest possible latency on ingress. Egress goes through a TC clsact qdisc.

### Fallback: TC ingress + TC egress

If the NIC driver does not support native XDP (common with `virtio` and `vmxnet3` and other virtual NICs), the collector falls back to TC on both sides:

```
TC ingress  ->  tc_ingress_tracker   (direction = INGRESS = 0)
TC egress   ->  tc_egress_tracker    (direction = EGRESS  = 1)
```

### Hook summary

| Hook | Direction | BPF function | When it attaches |
|------|-----------|--------------|------------------|
| XDP (native) | ingress | `xdp_connection_tracker` | Default, when the NIC has an XDP driver |
| TC clsact egress | egress | `tc_egress_tracker` | Always (paired with XDP or TC ingress) |
| TC clsact ingress | ingress | `tc_ingress_tracker` | Fallback when XDP is unavailable |

The active mode is logged at startup so you do not have to guess:

```
INFO  Attached XDP ingress hook on eth0
INFO  Attached TC egress hook on eth0 (clsact)
INFO  eBPF attachment mode: xdp+tc_egress
```

---

## Deployment

### Required packages

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    bpfcc-tools \
    linux-headers-$(uname -r) \
    libbpf-dev
```

### Production config

Put your config in `/etc/beacon-detect/config.yaml`:

```yaml
data_plane:
  interface: "eth0"
  export_interval: 60
  control_plane_host: "127.0.0.1"
  control_plane_port: 9090

control_plane:
  listen_address: "127.0.0.1"
  listen_port: 9090

detection:
  min_connections: 10
  cv_threshold: 0.15
  alert_threshold: 0.7
```

### Running

Terminal 1, control plane:

```bash
sudo ./venv/bin/python -m control_plane.server \
    --config /etc/beacon-detect/config.yaml
```

Terminal 2, data plane:

```bash
sudo ./venv/bin/python -m data_plane.collector \
    --config /etc/beacon-detect/config.yaml
```

### Tuning for high traffic

If exports are dropping events or memory is climbing, the levers worth touching are:

```yaml
data_plane:
  export_interval: 120        # less chatter
  max_buffer_size: 500000     # larger telemetry buffer
  ring_buffer_pages: 128      # larger eBPF ring buffer

control_plane:
  data_retention: 3600        # keep less history
  cleanup_interval: 120       # cull more often
```

### Whitelisting periodic services

The biggest source of false positives in real networks is legitimate periodic traffic. Suppress what you trust:

```yaml
whitelist:
  destination_ips:
    - "8.8.8.8"
    - "8.8.4.4"
    - "1.1.1.1"

  ports:
    - 53
    - 123
    - 67
    - 68

  pairs:
    - "10.0.0.5:169.254.169.254:80"
```

DNS over UDP/53 is intentionally not in the defaults. It is a common C2 channel, so add it only if you have other DNS visibility.

## Tests

```bash
pytest tests/
```

## License

MIT.
