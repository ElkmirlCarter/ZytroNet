# ZytroNet v3.0

Real-time network monitoring tool with a terminal dashboard and live web dashboard.

## What it does

- Monitors your internet connection in real-time with configurable polling intervals
- Tracks latency, packet loss, jitter, and connection quality per target
- Computes a composite quality score (0–100) with labels: Excellent, Good, Fair, Poor, Critical
- Detects and classifies faults: ONLINE, DEGRADED, ISP_FAILURE, OFFLINE
- Scans for devices on your network via ARP and pings each one to confirm liveness
- Identifies device vendors from MAC OUI prefixes
- Watches for network interface changes (IP/gateway switching) and updates state live
- Tracks session uptime, downtime, outage count, and mean outage duration
- Logs all status transitions and session events to an in-memory event log
- Renders a sparkline latency history in the terminal
- Live web dashboard at `http://localhost:5000`
- Generates an HTML report with charts on exit
- Generates an Excel (.xlsx) report on exit with conditional formatting and embedded line charts
- Audible beep alerts on outage and recovery events

## Requirements

Python 3.x and these libraries:

```
pip install psutil flask openpyxl
# or if pip doesn't work directly
python -m pip install psutil flask openpyxl
```

`psutil` — traffic monitoring  
`flask` — web dashboard  
`openpyxl` — Excel report export (optional but recommended)

## How to run

```
python ZYTRO_NET.py
```

## Options

```
--interval 5            Refresh interval in seconds (default: 3)
--targets 8.8.8.8 1.1.1.1
                        Ping targets (default: 8.8.8.8 1.1.1.1)
--ping-count 3          Pings per target per cycle (default: 3)
--no-web                Disable live web dashboard
--no-arp                Disable ARP device scanning
--no-color              Disable terminal colours
--web-port 5000         Web dashboard port (default: 5000)
--web-password SECRET   Enable HTTP basic auth on the web dashboard
--arp-interval 60       ARP scan interval in seconds (default: 60)
--history 50            Max metric samples kept in memory (default: 50)
--max-age 120           Max age of samples in seconds before eviction (default: 120)
--report FILE           HTML report output path (default: zytronet_report.html)
```

## Monitor specific devices

```
python ZYTRO_NET.py --targets 192.168.1.1 8.8.8.8 1.1.1.1
```

Point it at any host on your network — router, switch, server, or client machine. Useful for isolating where packet loss or latency is coming from.

## Web dashboard

The live dashboard at `http://localhost:5000` includes:

- Real-time latency, packet loss, jitter, and quality score
- Status pill and ambient background colour keyed to network state
- Live charts for latency, loss, traffic throughput, and quality score (click any chart to expand)
- Network map showing discovered devices — click a node to run an on-demand ping
- Full event log with filters (outages, recoveries, status changes, session start)
- Target management — add or remove ping targets without restarting
- Adjustable polling interval slider
- Pause/resume monitoring toggle
- Beep alert toggle
- Dark/light theme toggle (persisted to localStorage)
- Browser notification support for outages and recoveries
- One-click HTML report export

## Authentication

Use `--web-password` to protect the dashboard with HTTP basic auth. To avoid exposing the password in the process table, set the `ZYTRO_WEB_PASSWORD` environment variable instead:

```
export ZYTRO_WEB_PASSWORD=yourpassword
python ZYTRO_NET.py
```

The web server binds to `0.0.0.0` and is accessible on all interfaces. Credentials are transmitted unencrypted — use this on a trusted network or restrict access with a firewall.

## Terminal controls

| Key | Action |
|-----|--------|
| `P` | Pause / resume monitoring |
| `B` | Toggle beep alerts |
| `Ctrl+C` | Stop and generate reports |

## Reports

On exit (Ctrl+C), ZytroNet generates:

- **HTML report** (`zytronet_report.html`) — session summary, charts for latency, loss, quality score, and traffic, full event log, and per-target results
- **Excel report** (`zytronet_report.xlsx`) — Summary, Metrics History, Event Log, and Per-Target Results sheets with conditional status formatting and embedded line charts (requires `openpyxl`)

The HTML report is also available live from the web dashboard via the Export report button, or directly at `http://localhost:5000/report`.

## Notes

- ARP device scanning requires root/admin privileges for full discovery. The tool runs without it but with limited results.
- If `psutil` is not installed, traffic speed monitoring is disabled but everything else continues.
- If `flask` is not installed, the web dashboard is disabled automatically.
- If `openpyxl` is not installed, only the HTML report is generated on exit.
