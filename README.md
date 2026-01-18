# eBPF Beacon Detection System

A network beacon detection system using eBPF for packet capture and statistical analysis for identifying command-and-control (C2) beaconing patterns.

## Features

- **FFT Periodicity Analysis**: Detect regular communication patterns using Fast Fourier Transform
- **CV Scoring**: Coefficient of Variation analysis for interval consistency
- **Jitter Analysis**: Detect timing patterns even with randomization
- **Multi-channel Alerting**: Syslog, file, and webhook alert channels

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

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start Control Plane

```bash
cd beacon-detect
python3 -m control_plane.server -c config/config.yaml
```

### 3. Start Data Plane

```bash
cd beacon-detect
sudo python3 -m data_plane.collector -c ./config/config.yaml
```

### 4. Use CLI to Monitor

```bash
# Check system status (live/offline)
python3 -m control_plane.cli status

# View detected beacons
python3 -m control_plane.cli beacons

# View beacons with high score (>=80%)
python3 -m control_plane.cli beacons --min-score 0.8

# View long connections (>1 hour)
python3 -m control_plane.cli long-conns

# Live monitoring mode
python3 -m control_plane.cli watch

# Output as CSV
python3 -m control_plane.cli beacons --csv > beacons.csv
```

## CLI Commands

### `status`

Show system status (live/offline), uptime, and statistics.

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

Show detected beacon patterns with severity scoring.

```bash
python3 -m control_plane.cli beacons [options]
```

Options:
- `--min-score FLOAT` - Minimum beacon score (0.0-1.0)
- `--limit INT` - Maximum results to show
- `--csv, -o` - Output as CSV

Example output:
```
  SCORE   SEVERITY    SOURCE IP           DEST IP             PORT   PROTO  CONNS     INTERVAL   
  -----   --------    ---------           -------             ----   -----  -----     --------   
  94.2%   CRITICAL    10.0.0.100          203.0.113.50        443    TCP    156       60.0s      
  85.3%   HIGH        10.0.0.101          198.51.100.25       8080   TCP    89        30.0s      
  72.1%   MEDIUM      10.0.0.102          192.0.2.100         53     UDP    45        300.0s     
```

### `long-conns`

Show long-standing connections that may indicate persistent C2.

```bash
python3 -m control_plane.cli long-conns [options]
```

Options:
- `--min-duration INT` - Minimum duration in seconds (default: 3600)
- `--limit INT` - Maximum results to show
- `--csv, -o` - Output as CSV

### `connections`

Show all tracked connection pairs.

```bash
python3 -m control_plane.cli connections [options]
```

Options:
- `--limit INT` - Maximum results to show
- `--csv, -o` - Output as CSV

### `watch`

Live monitoring mode with auto-refresh.

```bash
python3 -m control_plane.cli watch [options]
```

Options:
- `--interval INT` - Refresh interval in seconds (default: 5)

Press `Ctrl+C` to exit watch mode.

## Remote Monitoring

Connect to a remote control plane:

```bash
python3 -m control_plane.cli --host 192.168.1.100 --port 9090 status
python3 -m control_plane.cli --host 192.168.1.100 beacons
python3 -m control_plane.cli --host 192.168.1.100 watch
```

## Configuration

Edit `config/config.yaml`:

```yaml
control_plane:
  listen_address: "0.0.0.0"
  listen_port: 9090

detection:
  min_connections: 10      # Minimum events before analysis
  cv_threshold: 0.15       # CV threshold for beacon detection
  alert_threshold: 0.7     # Score threshold for alerts
  jitter_threshold: 5.0    # Max timing jitter (seconds)
  analysis_interval: 60    # Analysis frequency (seconds)

alerting:
  syslog_enabled: true
  file_enabled: true
  file_path: "/var/log/beacon-detect/alerts.json"
  webhook_enabled: false
  webhook_url: ""

whitelist:
  source_ips: []
  destination_ips: []
  destination_ports: [53, 123]  # DNS, NTP
```

## Detection Methodology

### Beacon Score Calculation

The combined beacon score is calculated using three components:

1. **CV Score** (40%): Based on Coefficient of Variation of connection intervals
2. **Periodicity Score** (40%): FFT-based detection of regular patterns
3. **Jitter Score** (20%): Analysis of timing consistency

### Severity Levels

| Score | Severity | Description |
|-------|----------|-------------|
| ≥90%  | CRITICAL | High confidence beacon, immediate investigation |
| ≥80%  | HIGH     | Likely beacon activity |
| ≥70%  | MEDIUM   | Suspicious pattern, worth investigating |
| <70%  | LOW      | Possible false positive |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/status` | GET | Server status |
| `/api/v1/beacons` | GET | List detected beacons |
| `/api/v1/alerts` | GET | List alerts |
| `/api/v1/connections` | GET | List connection pairs |
| `/api/v1/config` | GET/POST | Get/update configuration |
| `/api/v1/telemetry` | POST | Receive telemetry data |
| `/api/v1/analyze` | POST | Trigger manual analysis |

## Deployment Guide

#### Required Software

**Ubuntu/Debian:**

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


#### Configuration

Edit `/etc/beacon-detect/config.yaml`:

```yaml
data_plane:
  interface: "eth0"  # Your network interface
  export_interval: 60
  control_plane_host: "127.0.0.1"
  control_plane_port: 9090

control_plane:
  listen_address: "127.0.0.1"  # Local only
  listen_port: 9090

detection:
  min_connections: 10
  cv_threshold: 0.15
  alert_threshold: 0.7
```

#### Running

**Terminal 1: Start control plane**

```bash
sudo ./venv/bin/python -m control_plane.server \
    --config /etc/beacon-detect/config.yaml
```

**Terminal 2: Start data plane**

```bash
sudo ./venv/bin/python -m data_plane.collector \
    --config /etc/beacon-detect/config.yaml
```

### Configuration Tuning

#### Performance Tuning

For high-traffic environments:

```yaml
data_plane:
  export_interval: 120  # Less frequent exports
  max_buffer_size: 500000  # Larger buffer
  ring_buffer_pages: 128  # More eBPF buffer

control_plane:
  data_retention: 3600  # Less retention
  cleanup_interval: 120  # More frequent cleanup
```

#### Whitelist Common Services

Reduce false positives by whitelisting known periodic services:

```yaml
whitelist:
  destination_ips:
    - "8.8.8.8"      # Google DNS
    - "8.8.4.4"      # Google DNS
    - "1.1.1.1"      # Cloudflare DNS
  
  ports:
    - 53            # DNS
    - 123           # NTP
    - 67            # DHCP
    - 68            # DHCP
  
  pairs:
    - "10.0.0.5:169.254.169.254:80"  # AWS metadata
```

## Testing

Run unit tests:

```bash
pytest tests/
```

## License

MIT License
