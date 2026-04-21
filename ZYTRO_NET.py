#!/usr/bin/env python3
"""
PulseNet Monitoring Engine v3.0
Real-time network monitoring with live web dashboard.
"""

import os
import sys
import re
import time
import json
import socket
import platform
import threading
import argparse
import statistics
import ipaddress
import subprocess
from datetime import datetime
from collections import deque

# ── Optional imports ──────────────────────────────────────────────────────────
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    from flask import Flask, Response, render_template_string
    FLASK_OK = True
except ImportError:
    FLASK_OK = False

# ── Platform ──────────────────────────────────────────────────────────────────
IS_WIN = platform.system() == "Windows"
IS_LIN = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"

# ── ANSI ──────────────────────────────────────────────────────────────────────
class A:
    RST  = "\033[0m";  BOLD = "\033[1m"
    RED  = "\033[91m"; GRN  = "\033[92m"; YLW  = "\033[93m"
    CYN  = "\033[96m"; WHT  = "\033[97m"; GRY  = "\033[90m"
    MGT  = "\033[95m"
    CLR  = "\033[2J\033[H"
    HIDE = "\033[?25l"
    SHOW = "\033[?25h"

NO_COLOR = False

def cl(text, *codes):
    if NO_COLOR: return str(text)
    return "".join(codes) + str(text) + A.RST

def status_col(s):
    return {"ONLINE": A.GRN, "DEGRADED": A.YLW,
            "ISP_FAILURE": A.YLW, "OFFLINE": A.RED}.get(s, A.GRY)

# ── Argument Parser ───────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="PulseNet v3.0 — Real-Time Network Monitor")
    p.add_argument("--interval",     type=float, default=3.0,
                   help="Refresh interval in seconds (default: 3)")
    p.add_argument("--targets",      nargs="+",  default=["8.8.8.8", "1.1.1.1"],
                   help="Ping targets (default: 8.8.8.8 1.1.1.1)")
    p.add_argument("--ping-count",   type=int,   default=3,
                   help="Pings per target per cycle (default: 3)")
    p.add_argument("--report",       type=str,   default="pulsenet_report.html",
                   help="HTML report output path (default: pulsenet_report.html)")
    p.add_argument("--web-port",     type=int,   default=5000,
                   help="Live web dashboard port (default: 5000)")
    p.add_argument("--no-arp",       action="store_true",
                   help="Disable ARP device scanning")
    p.add_argument("--no-web",       action="store_true",
                   help="Disable live web dashboard")
    p.add_argument("--no-color",     action="store_true",
                   help="Disable terminal colors")
    p.add_argument("--arp-interval", type=float, default=60.0,
                   help="ARP scan interval in seconds (default: 60)")
    p.add_argument("--history",      type=int,   default=50,
                   help="Max metric samples in memory (default: 50)")
    p.add_argument("--max-age",      type=float, default=120,
                   help="Max age of data in seconds before clearing (default: 120)")
    return p.parse_args()

# ── Privilege Check ───────────────────────────────────────────────────────────
def is_root():
    if IS_WIN:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0

# ── Utilities ─────────────────────────────────────────────────────────────────
def fmt_bytes(b):
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if abs(b) < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"

def fmt_speed(bps): return fmt_bytes(bps) + "/s"

def fmt_dur(s):
    h, m, sec = int(s // 3600), int((s % 3600) // 60), int(s % 60)
    if h:  return f"{h}h {m}m {sec}s"
    if m:  return f"{m}m {sec}s"
    return f"{sec}s"

def sparkline(vals):
    bars = " ▁▂▃▄▅▆▇█"
    if not vals: return cl("no data", A.GRY)
    mn, mx = min(vals), max(vals)
    rng = mx - mn if mx != mn else 1
    out = ""
    for v in vals:
        idx = int((v - mn) / rng * (len(bars) - 1))
        col = A.GRN if v < 60 else A.YLW if v < 150 else A.RED
        out += cl(bars[idx], col)
    return out

def quality_score(latency, loss, jitter):
    if latency is None: return 0
    s = (max(0, 100 - latency / 3) * 0.50 +
         max(0, 100 - loss * 4)    * 0.35 +
         max(0, 100 - jitter * 2)  * 0.15)
    return round(max(0, min(100, s)), 1)

def score_label(score):
    if score >= 85: return "Excellent"
    if score >= 70: return "Good"
    if score >= 50: return "Fair"
    if score >= 25: return "Poor"
    return "Critical"

def score_color_css(score):
    if score >= 85: return "#00ff88"
    if score >= 70: return "#84cc16"
    if score >= 50: return "#ffd700"
    if score >= 25: return "#ff8c00"
    return "#ff4444"

def beep():
    try:
        if IS_WIN:
            import winsound
            winsound.Beep(1000, 300)
            winsound.Beep(1200, 300)
        else:
            sys.stdout.write("\a\a")
            sys.stdout.flush()
    except: pass

# ── Network Info ──────────────────────────────────────────────────────────────
def get_primary_interface():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        if PSUTIL_OK:
            for iface, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and a.address == local_ip:
                        return iface, local_ip
        return None, local_ip
    except: return None, "Unknown"

def get_gateway():
    try:
        if IS_WIN:
            out = subprocess.check_output("ipconfig", text=True,
                                          stderr=subprocess.DEVNULL)
            for line in out.split("\n"):
                if "Default Gateway" in line:
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                    if m: return m.group(1)
        elif IS_LIN:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                text=True, stderr=subprocess.DEVNULL)
            m = re.search(r"default via (\S+)", out)
            if m: return m.group(1)
        elif IS_MAC:
            out = subprocess.check_output(
                ["netstat", "-rn"], text=True, stderr=subprocess.DEVNULL)
            for line in out.split("\n"):
                if line.startswith("default"):
                    parts = line.split()
                    if len(parts) >= 2: return parts[1]
    except: pass
    return "Unknown"

def get_public_ip():
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except: return "Unavailable"

def get_local_subnet(ip):
    try:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except: return None

# ── Ping & Connectivity ───────────────────────────────────────────────────────
def ping_host(host, count=3):
    latencies, lost = [], 0
    for _ in range(count):
        cmd = (["ping", "-n", "1", "-w", "1000", host] if IS_WIN
               else ["ping", "-c", "1", "-W", "1", host])
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=3)
            if r.returncode == 0:
                m = re.search(r"time[=<]\s*(\d+\.?\d*)", r.stdout)
                if m: latencies.append(float(m.group(1)))
                else: lost += 1
            else: lost += 1
        except subprocess.TimeoutExpired:
            lost += 1
        except Exception:
            lost += 1
    avg    = sum(latencies) / len(latencies) if latencies else None
    loss   = (lost / count) * 100
    jitter = statistics.stdev(latencies) if len(latencies) >= 2 else 0.0
    return avg, loss, jitter

def check_dns():
    try:
        # Create a temporary socket with timeout instead of setting global default
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.close()
        # Use getaddrinfo which respects socket timeout better
        socket.getaddrinfo("google.com", 80, socket.AF_INET, socket.SOCK_STREAM)
        return True
    except Exception:
        return False

def get_network_status(gateway, targets, ping_count):
    res = {
        "status": "UNKNOWN", "gateway_ok": False, "internet_ok": False,
        "dns_ok": False, "latency": None, "loss": 100.0,
        "jitter": 0.0, "score": 0, "score_label": "Critical",
        "target_results": {}
    }
    if gateway and gateway != "Unknown":
        _, gw_loss, _ = ping_host(gateway, count=2)
        res["gateway_ok"] = gw_loss < 50

    all_lat, all_loss = [], []
    for t in targets:
        lat, loss, jitter = ping_host(t, count=ping_count)
        res["target_results"][t] = {"latency": lat, "loss": loss, "jitter": jitter}
        if lat is not None: all_lat.append(lat)
        all_loss.append(loss)

    if all_lat:
        res["latency"] = sum(all_lat) / len(all_lat)
        res["jitter"]  = statistics.stdev(all_lat) if len(all_lat) >= 2 else 0.0
    avg_loss = sum(all_loss) / len(all_loss) if all_loss else 100.0
    res["loss"]        = avg_loss
    res["internet_ok"] = avg_loss < 50
    res["dns_ok"]      = check_dns()

    if not res["gateway_ok"] and not res["internet_ok"]:
        res["status"] = "OFFLINE"
    elif res["gateway_ok"] and not res["internet_ok"]:
        res["status"] = "ISP_FAILURE"
    elif res["internet_ok"] and (avg_loss > 10 or
         (res["latency"] and res["latency"] > 200)):
        res["status"] = "DEGRADED"
    elif res["internet_ok"]:
        res["status"] = "ONLINE"
    else:
        res["status"] = "OFFLINE"

    res["score"]       = quality_score(res["latency"], res["loss"], res["jitter"])
    res["score_label"] = score_label(res["score"])
    return res

# ── Traffic Monitor ───────────────────────────────────────────────────────────
class TrafficMonitor:
    def __init__(self, iface=None):
        self.iface    = iface
        self._lock    = threading.Lock()
        self._last    = self._io()
        self._last_t  = time.time()
        self.up_speed = 0.0
        self.dn_speed = 0.0
        self.total_sent = 0
        self.total_recv = 0

    def _io(self):
        if not PSUTIL_OK: return None
        try:
            if self.iface:
                return psutil.net_io_counters(pernic=True).get(self.iface)
            return psutil.net_io_counters()
        except: return None

    def update(self):
        cur = self._io(); now = time.time()
        if cur is None or self._last is None: return
        dt = now - self._last_t
        if dt <= 0: return
        with self._lock:
            self.up_speed   = (cur.bytes_sent - self._last.bytes_sent) / dt
            self.dn_speed   = (cur.bytes_recv - self._last.bytes_recv) / dt
            self.total_sent = cur.bytes_sent
            self.total_recv = cur.bytes_recv
        self._last = cur; self._last_t = now

    def snap(self):
        with self._lock:
            return {"up": self.up_speed, "dn": self.dn_speed,
                    "sent": self.total_sent, "recv": self.total_recv}

# ── ARP Scanner ───────────────────────────────────────────────────────────────
class ARPScanner:
    OUI = {
        "00:50:56": "VMware",       "00:0C:29": "VMware",
        "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
        "52:54:00": "QEMU/KVM",     "00:25:00": "Apple",
        "AC:DE:48": "Apple",        "A4:C3:F0": "Apple",
        "00:50:F2": "Microsoft",    "28:D2:44": "Samsung",
        "00:26:B9": "Dell",         "18:03:73": "Dell",
        "00:21:70": "Cisco",        "00:1B:D4": "Cisco",
        "EC:08:6B": "TP-Link",      "50:C7:BF": "TP-Link",
        "14:CC:20": "TP-Link",      "00:17:88": "Philips Hue",
        "B4:E6:2D": "Netgear",      "C8:3A:35": "Tenda",
    }
    EXCLUDED = [
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("239.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("255.255.255.255/32"),
        ipaddress.ip_network("0.0.0.0/8"),
    ]

    def __init__(self, enabled=True, local_ip=None):
        self.enabled   = enabled
        self.local_ip  = local_ip
        self.subnet    = get_local_subnet(local_ip) if local_ip else None
        self.devices   = []
        self.last_scan = 0
        self._lock     = threading.Lock()
        self._running  = False

    def _valid_ip(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            if ip == self.local_ip: return False
            for net in self.EXCLUDED:
                if addr in net: return False
            if self.subnet:
                if addr not in ipaddress.ip_network(self.subnet, strict=False):
                    return False
            return True
        except: return False

    def _vendor(self, mac):
        return self.OUI.get(mac.upper()[:8], "Unknown")

    def _ping_check(self, ip):
        cmd = (["ping", "-n", "1", "-w", "500", ip] if IS_WIN
               else ["ping", "-c", "1", "-W", "1", ip])
        try:
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=2)
            return r.returncode == 0
        except: return False

    def _scan(self):
        if not self.enabled: return []
        found, seen = [], set()
        try:
            out = subprocess.check_output(
                ["arp", "-a"], text=True,
                stderr=subprocess.DEVNULL, timeout=15)
            ip_re  = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
            mac_re = re.compile(
                r"\b([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})\b")
            for line in out.split("\n"):
                im = ip_re.search(line); mm = mac_re.search(line)
                if not im or not mm: continue
                ip  = im.group(1)
                mac = mm.group(1).upper().replace("-", ":")
                if not self._valid_ip(ip): continue
                if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"): continue
                if ip in seen: continue
                seen.add(ip)
                found.append({"ip": ip, "mac": mac,
                              "vendor": self._vendor(mac),
                              "alive": self._ping_check(ip)})
        except: pass
        return found

    def start(self, interval=60):
        self._running = True
        def loop():
            while self._running:
                d = self._scan()
                with self._lock:
                    self.devices   = d
                    self.last_scan = time.time()
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()

    def stop(self): self._running = False

    def get(self):
        with self._lock:
            return list(self.devices), self.last_scan

# ── Event Log (in-memory) ─────────────────────────────────────────────────────
class EventLog:
    def __init__(self, maxlen=500, max_age=3600):
        self._lock  = threading.Lock()
        self.events = []
        self.maxlen = maxlen
        self.max_age = max_age

    def log(self, event, detail="", prev="", new="", duration=None):
        rec = {
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event":        event,
            "detail":       detail,
            "prev_status":  prev,
            "new_status":   new,
            "duration_sec": duration or ""
        }
        with self._lock:
            self.events.append(rec)
            now = time.time()
            cutoff = now - self.max_age
            self.events = [e for e in self.events if datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S").timestamp() > cutoff]
            if len(self.events) > self.maxlen:
                self.events = self.events[-self.maxlen:]

    def recent(self, n=8):
        with self._lock: return list(self.events)[-n:]

    def all(self):
        with self._lock: return list(self.events)

# ── Metrics Store (in-memory) ─────────────────────────────────────────────────
class MetricsStore:
    def __init__(self, maxlen=120, max_age=3600):
        self._lock   = threading.Lock()
        self.records = []
        self.maxlen = maxlen
        self.max_age = max_age

    def add(self, net, traffic):
        rec = {
            "ts":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status":  net["status"],
            "latency": round(net["latency"], 2) if net["latency"] else None,
            "loss":    round(net["loss"], 2),
            "jitter":  round(net["jitter"], 2),
            "score":   net["score"],
            "up_bps":  round(traffic["up"], 2),
            "dn_bps":  round(traffic["dn"], 2),
            "dns_ok":  int(net["dns_ok"]),
            "gw_ok":   int(net["gateway_ok"]),
        }
        with self._lock:
            self.records.append(rec)
            now = time.time()
            cutoff = now - self.max_age
            self.records = [r for r in self.records if datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S").timestamp() > cutoff]
            if len(self.records) > self.maxlen:
                self.records = self.records[-self.maxlen:]

    def all(self):
        with self._lock: return list(self.records)

# ── Session Tracker ───────────────────────────────────────────────────────────
class Session:
    def __init__(self):
        self.start      = time.time()
        self.outages    = 0
        self.downtime   = 0.0
        self._out_start = None
        self._last_st   = None
        self._durations = []
        self._lock      = threading.Lock()

    def update(self, status, log: EventLog):
        now    = time.time()
        online = status in ("ONLINE", "DEGRADED")
        with self._lock:
            prev = self._last_st
            if prev is None:
                self._last_st = status
                log.log("SESSION_START", new=status, detail="Monitoring started")
                return
            if prev in ("ONLINE", "DEGRADED") and not online:
                self.outages    += 1
                self._out_start  = now
                self._last_st    = status
                log.log("OUTAGE_START", prev=prev, new=status,
                        detail=f"Network went {status}")
                beep()
            elif prev not in ("ONLINE", "DEGRADED") and online:
                dur = 0.0
                if self._out_start:
                    dur = round(now - self._out_start, 1)
                    self.downtime += dur
                    self._durations.append(dur)
                    self._out_start = None
                self._last_st = status
                log.log("RECOVERY", prev=prev, new=status,
                        detail="Network recovered", duration=dur)
                beep()
            elif prev != status:
                self._last_st = status
                log.log("STATUS_CHANGE", prev=prev, new=status,
                        detail=f"{prev} → {status}")

    def summary(self):
        with self._lock:
            now  = time.time()
            tot  = now - self.start
            down = self.downtime + (now - self._out_start if self._out_start else 0)
            up   = max(0.0, tot - down)
            pct  = (up / tot * 100) if tot > 0 else 100.0
            mtbo = statistics.mean(self._durations) if self._durations else None
            return {"total": tot, "uptime": up, "downtime": down,
                    "up_pct": pct, "outages": self.outages, "mtbo": mtbo}

# ── Pause Controller ──────────────────────────────────────────────────────────
class PauseController:
    def __init__(self):
        self.paused   = False
        self._running = True
        self._lock    = threading.Lock()

    def start(self):
        threading.Thread(target=self._listen, daemon=True).start()

    def _listen(self):
        if IS_WIN:
            import msvcrt
            while self._running:
                if msvcrt.kbhit():
                    try:
                        ch = msvcrt.getch().decode("utf-8", "ignore").lower()
                        if ch == "p":
                            with self._lock: self.paused = not self.paused
                    except (UnicodeDecodeError, AttributeError):
                        pass  # Ignore special keys that can't be decoded
                time.sleep(0.05)
        else:
            import tty, termios, select
            fd  = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while self._running:
                    if select.select([sys.stdin], [], [], 0.05)[0]:
                        ch = sys.stdin.read(1).lower()
                        if ch == "p":
                            with self._lock: self.paused = not self.paused
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)

    def is_paused(self):
        with self._lock: return self.paused

    def stop(self): self._running = False

# ── Terminal Dashboard ────────────────────────────────────────────────────────
class TerminalDashboard:
    W = 62

    def _hdr(self, title):
        pad = self.W - len(title) - 4
        return cl(f"╭─ {title} " + "─" * pad + "╮", A.CYN, A.BOLD)

    def _ftr(self):
        return cl("╰" + "─" * (self.W - 2) + "╯", A.CYN)

    def _row(self, label, val, vc=None):
        lbl = cl(f"  {label:<22}", A.GRY)
        v   = cl(str(val), vc) if vc else str(val)
        return f"{lbl}{v}"

    def draw(self, net, traffic, devices, last_scan,
             local_ip, public_ip, gateway, iface,
             session, log, metrics_store, lat_hist,
             paused, no_priv, args):

        lines = []
        add   = lines.append

        status = net["status"]
        lat    = net["latency"]
        loss   = net["loss"]
        jit    = net["jitter"]
        score  = net["score"]
        sc     = status_col(status)
        now    = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

        # ── Title ────────────────────────────────────────────────────────────
        add("")
        add(cl("  ◈ PULSENET", A.CYN, A.BOLD) +
            cl(" v3.0", A.GRY) + "  " + cl(now, A.GRY))
        add(cl("  " + "═" * self.W, A.CYN))
        if paused:
            add(cl("  ⏸  PAUSED — press P to resume", A.YLW, A.BOLD))
        add("")

        # ── Network Status ────────────────────────────────────────────────────
        add(self._hdr("Network Status"))
        add(cl(f"  ● {status}", sc, A.BOLD))

        lat_c = A.GRN if lat and lat < 80 else A.YLW if lat and lat < 200 else A.RED
        add(self._row("Latency",     f"{lat:.1f} ms" if lat else "N/A", lat_c))
        add(self._row("Packet Loss", f"{loss:.1f}%",
            A.GRN if loss == 0 else A.YLW if loss < 15 else A.RED))
        add(self._row("Jitter",      f"{jit:.1f} ms",
            A.GRN if jit < 10 else A.YLW if jit < 30 else A.RED))
        add(self._row("DNS",
            cl("Resolving ✓", A.GRN) if net["dns_ok"] else cl("Failed ✗", A.RED)))

        if not net["gateway_ok"] and not net["internet_ok"]:
            fault = cl("Local network failure", A.RED)
        elif net["gateway_ok"] and not net["internet_ok"]:
            fault = cl("ISP / upstream failure", A.YLW)
        else:
            fault = cl("None detected", A.GRN)
        add(self._row("Fault Location", fault))

        sc_term = A.GRN if score >= 85 else A.YLW if score >= 50 else A.RED
        add(self._row("Quality Score",
            cl(f"{score}/100  {net['score_label']}", sc_term, A.BOLD)))
        add(self._ftr())
        add("")

        # ── Latency Sparkline ─────────────────────────────────────────────────
        if lat_hist:
            vals = list(lat_hist)
            mn, mx, avg = min(vals), max(vals), sum(vals) / len(vals)
            add(cl("  Latency History", A.GRY, A.BOLD))
            add(f"  {sparkline(vals)}")
            add(f"  {cl(f'min {mn:.0f}ms', A.GRN)}   "
                f"{cl(f'avg {avg:.0f}ms', A.CYN)}   "
                f"{cl(f'max {mx:.0f}ms', A.RED)}")
            add("")

        # ── Target Results ────────────────────────────────────────────────────
        add(self._hdr("Target Results"))
        for t, r in net["target_results"].items():
            tl  = f"{r['latency']:.1f} ms" if r["latency"] else "Timeout"
            tlc = A.GRN if r["latency"] and r["latency"] < 100 else A.RED
            add(self._row(t,
                cl(tl, tlc) +
                cl(f"  jitter {r['jitter']:.1f}ms  loss {r['loss']:.0f}%", A.GRY)))
        add(self._ftr())
        add("")

        # ── Traffic ───────────────────────────────────────────────────────────
        add(self._hdr(f"Traffic  [{iface or 'Unknown'}]"))
        add(self._row("↑ Upload Speed",   fmt_speed(traffic["up"]),   A.YLW))
        add(self._row("↓ Download Speed", fmt_speed(traffic["dn"]),   A.GRN))
        add(self._row("Total Sent",       fmt_bytes(traffic["sent"]), A.GRY))
        add(self._row("Total Received",   fmt_bytes(traffic["recv"]), A.GRY))
        add(self._ftr())
        add("")

        # ── System ────────────────────────────────────────────────────────────
        add(self._hdr("System"))
        add(self._row("Local IP",   local_ip,  A.CYN))
        add(self._row("Public IP",  public_ip, A.MGT))
        add(self._row("Gateway",    gateway,   A.CYN))
        add(self._ftr())
        add("")

        # ── Devices ───────────────────────────────────────────────────────────
        add(self._hdr("Connected Devices"))
        if args.no_arp:
            add(cl("  ARP scanning disabled", A.GRY))
        elif no_priv:
            add(cl("  ⚠  Run as admin for full device discovery", A.YLW))
        if devices:
            age = int(time.time() - last_scan) if last_scan else 0
            add(cl(f"  {'IP':<18}{'Vendor':<16}Status", A.GRY))
            add(cl("  " + "─" * (self.W - 4), A.GRY))
            for d in devices[:6]:
                alive = cl("● Online", A.GRN) if d["alive"] else cl("○ Stale", A.GRY)
                add(f"  {cl(d['ip'], A.WHT):<28}"
                    f"{cl(d['vendor'], A.GRY):<16}{alive}")
            add(cl(f"\n  {len(devices)} device(s)", A.WHT) +
                cl(f"   scan {age}s ago", A.GRY))
        else:
            add(cl("  Scanning...", A.GRY))
        add(self._ftr())
        add("")

        # ── Session ───────────────────────────────────────────────────────────
        ss = session.summary()
        add(self._hdr("Session"))
        add(self._row("Runtime",  fmt_dur(ss["total"]),    A.WHT))
        add(self._row("Uptime",   fmt_dur(ss["uptime"]),   A.GRN))
        add(self._row("Downtime", fmt_dur(ss["downtime"]),
            A.RED if ss["downtime"] > 0 else A.GRY))
        up_c = A.GRN if ss["up_pct"] > 95 else A.YLW if ss["up_pct"] > 80 else A.RED
        add(self._row("Uptime %", f"{ss['up_pct']:.2f}%", up_c))
        add(self._row("Outages",  str(ss["outages"]),
            A.RED if ss["outages"] > 0 else A.GRN))
        if ss["mtbo"]:
            add(self._row("Avg Outage", fmt_dur(ss["mtbo"]), A.YLW))
        add(self._ftr())
        add("")

        # ── Recent Events ─────────────────────────────────────────────────────
        add(self._hdr("Recent Events"))
        evts = log.recent(4)
        if evts:
            for ev in reversed(evts):
                add(f"  {cl(ev['timestamp'], A.GRY)}  "
                    f"{cl(ev['event'][:16], A.CYN):<24}  "
                    f"{cl(ev['detail'], A.WHT)}")
        else:
            add(cl("  No events yet.", A.GRY))
        add(self._ftr())
        add("")

        # ── Footer ────────────────────────────────────────────────────────────
        mc = len(metrics_store.all())
        add(cl(f"  {mc} samples", A.GRY) +
            cl("  │  P = pause/resume", A.GRY) +
            cl("  │  CTRL+C = stop + report", A.GRY))
        if not args.no_web and FLASK_OK:
            add(cl(f"  Live web dashboard → http://localhost:{args.web_port}", A.CYN))
        add("")

        # ── Render (clear + redraw) ───────────────────────────────────────────
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n".join(lines))


# ── Web Dashboard HTML ────────────────────────────────────────────────────────
WEB_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PulseNet Live</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#080d14;--surf:#0f1724;--surf2:#162030;--bdr:#1e2d40;--text:#e2e8f0;
  --muted:#4a6080;--cyan:#00d4ff;--green:#00ff88;--yellow:#ffd700;
  --red:#ff4444;--orange:#ff8c00;--purple:#a855f7}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Syne',sans-serif;min-height:100vh}
body::before{content:'';position:fixed;inset:0;
  background:radial-gradient(ellipse at 20% 20%,#00d4ff08,transparent 50%),
             radial-gradient(ellipse at 80% 80%,#00ff8806,transparent 50%);
  pointer-events:none;z-index:0}
header{position:relative;z-index:1;padding:24px 36px;border-bottom:1px solid var(--bdr);
  display:flex;justify-content:space-between;align-items:center}
.logo{font-size:20px;font-weight:800;color:var(--cyan)}
.logo span{color:var(--muted);font-weight:400;font-size:13px;margin-left:8px}
.hright{display:flex;align-items:center;gap:16px}
.live{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--green);
  font-family:'JetBrains Mono',monospace}
.ldot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.lupd{font-size:11px;color:var(--muted);font-family:'JetBrains Mono',monospace}
.tbtn{background:var(--surf);border:1px solid var(--bdr);color:var(--muted);
  padding:5px 10px;border-radius:6px;cursor:pointer;font-size:11px;transition:.2s}
.tbtn:hover{color:var(--text);border-color:var(--cyan)}
.wrap{position:relative;z-index:1;max-width:1380px;margin:0 auto;padding:24px 36px}

/* Score Hero */
.hero{background:linear-gradient(135deg,#00d4ff18,#00ff8810);border:1px solid var(--bdr);
  border-radius:14px;padding:24px;margin-bottom:22px;display:flex;align-items:center;gap:28px;
  flex-wrap:wrap}
.sring{position:relative;width:90px;height:90px;flex-shrink:0}
.sring svg{transform:rotate(-90deg)}
.strk{fill:none;stroke:var(--bdr);stroke-width:8}
.sfll{fill:none;stroke-width:8;stroke-linecap:round;transition:stroke-dashoffset .8s ease,stroke .5s}
.snum{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;
  justify-content:center;font-family:'JetBrains Mono',monospace}
.snum .n{font-size:20px;font-weight:700;line-height:1}
.snum .l{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.sinfo h2{font-size:26px;font-weight:800;margin-bottom:3px}
.sinfo .sub{color:var(--muted);font-size:12px}
.smeta{margin-left:auto;display:flex;gap:20px;flex-wrap:wrap}
.smi{text-align:right}
.smi .v{font-family:'JetBrains Mono',monospace;font-size:17px;font-weight:700}
.smi .k{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}

/* Grid */
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px}
.g2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:16px}
.g1{display:grid;grid-template-columns:1fr;gap:16px;margin-bottom:16px}
@media(max-width:900px){.g3,.g2{grid-template-columns:1fr}.smeta{margin-left:0}}

/* Cards */
.card{background:var(--surf);border:1px solid var(--bdr);border-radius:11px;padding:20px;
  position:relative;overflow:hidden;transition:border-color .2s}
.card:hover{border-color:#2a3d55}
.card::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:var(--ac,var(--cyan));opacity:.7}
.ct{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);
  font-weight:600;margin-bottom:14px}
.sbig{font-family:'JetBrains Mono',monospace;font-size:30px;font-weight:700;line-height:1}
.su{font-size:13px;color:var(--muted);font-weight:400}
.rows{display:flex;flex-direction:column;gap:6px}
.ri{display:flex;justify-content:space-between;align-items:center;padding:6px 0;
  border-bottom:1px solid var(--bdr)}
.ri:last-child{border-bottom:none}
.rl{font-size:11px;color:var(--muted)}
.rv{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600}
.badge{display:inline-flex;align-items:center;gap:7px;padding:5px 12px;border-radius:16px;
  font-size:12px;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:.5px}
.bdot{width:7px;height:7px;border-radius:50%}

/* Timeline */
.tl{display:flex;height:22px;border-radius:5px;overflow:hidden;gap:1px;margin-top:8px}
.tls{flex:1;min-width:2px;cursor:default}
.tls:hover{opacity:.75}
.tleg{display:flex;gap:14px;margin-top:8px;font-size:11px;color:var(--muted)}

/* Table */
table{width:100%;border-collapse:collapse;font-size:11px}
th{text-align:left;padding:7px 10px;color:var(--muted);font-size:9px;text-transform:uppercase;
  letter-spacing:.5px;border-bottom:1px solid var(--bdr);font-weight:600}
td{padding:7px 10px;border-bottom:1px solid var(--bdr);font-family:'JetBrains Mono',monospace;font-size:11px}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
.eb{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;
  font-weight:700;color:#fff;font-family:'JetBrains Mono',monospace}
footer{text-align:center;padding:20px;color:var(--muted);font-size:10px;
  border-top:1px solid var(--bdr);margin-top:8px;font-family:'JetBrains Mono',monospace}
body.light{--bg:#f0f4f8;--surf:#fff;--surf2:#f8fafc;--bdr:#e2e8f0;--text:#1a2332;--muted:#94a3b8}
</style>
</head>
<body>
<header>
  <div class="logo">◈ PulseNet <span>Live Monitor v3.0</span></div>
  <div class="hright">
    <div class="live"><div class="ldot"></div>LIVE</div>
    <div class="lupd" id="upd">Connecting...</div>
    <button class="tbtn" onclick="document.body.classList.toggle('light')">⬤ Theme</button>
  </div>
</header>
<div class="wrap">

<!-- Score Hero -->
<div class="hero">
  <div class="sring">
    <svg viewBox="0 0 100 100" width="90" height="90">
      <circle class="strk" cx="50" cy="50" r="42"/>
      <circle class="sfll" id="sarc" cx="50" cy="50" r="42"
              stroke-dasharray="263.9" stroke-dashoffset="263.9" stroke="var(--cyan)"/>
    </svg>
    <div class="snum"><div class="n" id="snum">--</div><div class="l">Score</div></div>
  </div>
  <div class="sinfo">
    <h2 id="slbl">Connecting...</h2>
    <div class="sub" id="sst">Waiting for data</div>
  </div>
  <div class="smeta">
    <div class="smi"><div class="v" id="hlat">--</div><div class="k">Latency</div></div>
    <div class="smi"><div class="v" id="hloss">--</div><div class="k">Packet Loss</div></div>
    <div class="smi"><div class="v" id="hup">--</div><div class="k">Uptime</div></div>
  </div>
</div>

<!-- Row 1: Status / System / Traffic -->
<div class="g3">
  <div class="card" style="--ac:var(--cyan)">
    <div class="ct">Network Status</div>
    <div id="sbadge" class="badge" style="background:#00d4ff22;color:var(--cyan);margin-bottom:12px">
      <div class="bdot" style="background:var(--cyan)"></div>--
    </div>
    <div class="rows">
      <div class="ri"><span class="rl">DNS</span><span class="rv" id="dns">--</span></div>
      <div class="ri"><span class="rl">Fault</span><span class="rv" id="fault">--</span></div>
      <div class="ri"><span class="rl">Jitter</span><span class="rv" id="jitter">--</span></div>
    </div>
  </div>
  <div class="card" style="--ac:var(--purple)">
    <div class="ct">System</div>
    <div class="rows">
      <div class="ri"><span class="rl">Local IP</span><span class="rv" id="lip">--</span></div>
      <div class="ri"><span class="rl">Public IP</span><span class="rv" id="pip" style="color:var(--purple)">--</span></div>
      <div class="ri"><span class="rl">Gateway</span><span class="rv" id="gw">--</span></div>
      <div class="ri"><span class="rl">Interface</span><span class="rv" id="ifc">--</span></div>
    </div>
  </div>
  <div class="card" style="--ac:var(--green)">
    <div class="ct">Traffic</div>
    <div style="margin-bottom:10px">
      <div style="font-size:9px;color:var(--muted);margin-bottom:3px">↑ UPLOAD</div>
      <div class="sbig" id="ups" style="color:var(--yellow)">--</div>
    </div>
    <div>
      <div style="font-size:9px;color:var(--muted);margin-bottom:3px">↓ DOWNLOAD</div>
      <div class="sbig" id="dns2" style="color:var(--green)">--</div>
    </div>
    <div class="rows" style="margin-top:12px">
      <div class="ri"><span class="rl">Total Sent</span><span class="rv" id="tsent">--</span></div>
      <div class="ri"><span class="rl">Total Recv</span><span class="rv" id="trecv">--</span></div>
    </div>
  </div>
</div>

<!-- Charts Row -->
<div class="g2">
  <div class="card" style="--ac:var(--cyan)">
    <div class="ct">Latency (ms)</div>
    <canvas id="cLat" height="140"></canvas>
  </div>
  <div class="card" style="--ac:var(--yellow)">
    <div class="ct">Packet Loss (%)</div>
    <canvas id="cLoss" height="140"></canvas>
  </div>
  <div class="card" style="--ac:var(--green)">
    <div class="ct">Network Speed (KB/s)</div>
    <canvas id="cSpeed" height="140"></canvas>
  </div>
  <div class="card" style="--ac:var(--purple)">
    <div class="ct">Quality Score</div>
    <canvas id="cScore" height="140"></canvas>
  </div>
</div>

<!-- Timeline -->
<div class="card" style="--ac:var(--green);margin-bottom:16px">
  <div class="ct">Connectivity Timeline</div>
  <div class="tl" id="tl"></div>
  <div class="tleg">
    <span><span style="color:#00ff88">●</span> Online</span>
    <span><span style="color:#ffd700">●</span> Degraded</span>
    <span><span style="color:#ff8c00">●</span> ISP Failure</span>
    <span><span style="color:#ff4444">●</span> Offline</span>
  </div>
</div>

<!-- Session / Targets / Devices -->
<div class="g3" style="margin-bottom:16px">
  <div class="card" style="--ac:var(--cyan)">
    <div class="ct">Session</div>
    <div class="rows">
      <div class="ri"><span class="rl">Runtime</span><span class="rv" id="rt">--</span></div>
      <div class="ri"><span class="rl">Uptime</span><span class="rv" id="ut" style="color:var(--green)">--</span></div>
      <div class="ri"><span class="rl">Downtime</span><span class="rv" id="dt" style="color:var(--red)">--</span></div>
      <div class="ri"><span class="rl">Uptime %</span><span class="rv" id="utp">--</span></div>
      <div class="ri"><span class="rl">Outages</span><span class="rv" id="ot">--</span></div>
      <div class="ri"><span class="rl">Avg Outage</span><span class="rv" id="mtbo">--</span></div>
    </div>
  </div>
  <div class="card" style="--ac:var(--yellow)">
    <div class="ct">Target Results</div>
    <div class="rows" id="trows"><div style="color:var(--muted);font-size:11px">Loading...</div></div>
  </div>
  <div class="card" style="--ac:var(--orange)">
    <div class="ct">Connected Devices</div>
    <div id="devs" style="font-size:11px;color:var(--muted)">Scanning...</div>
  </div>
</div>

<!-- Events -->
<div class="card" style="--ac:var(--red);margin-bottom:16px">
  <div class="ct">Event Log</div>
  <table>
    <thead><tr><th>Timestamp</th><th>Event</th><th>Detail</th><th>Duration</th></tr></thead>
    <tbody id="evrows"><tr><td colspan="4" style="color:var(--muted)">No events yet</td></tr></tbody>
  </table>
</div>

</div>
<footer>◈ PulseNet v3.0 &nbsp;·&nbsp; Live Dashboard &nbsp;·&nbsp; Auto-reconnect enabled</footer>

<script>
const SC = {ONLINE:'#00ff88',DEGRADED:'#ffd700',ISP_FAILURE:'#ff8c00',OFFLINE:'#ff4444',UNKNOWN:'#4a6080'};
const EC = {OUTAGE_START:'#ff4444',RECOVERY:'#00ff88',STATUS_CHANGE:'#ffd700',SESSION_START:'#00d4ff'};
const gc = 'rgba(255,255,255,0.04)';
const bo = {
  responsive:true,animation:false,
  plugins:{legend:{labels:{color:'#4a6080',font:{size:10,family:"'JetBrains Mono'"}}}},
  scales:{x:{ticks:{color:'#4a6080',maxRotation:0,font:{size:9}},grid:{color:gc}},
          y:{ticks:{color:'#4a6080',font:{size:9}},grid:{color:gc}}}
};
function mkLine(id,color,label){
  return new Chart(document.getElementById(id),{type:'line',data:{labels:[],datasets:[{
    label,data:[],borderColor:color,backgroundColor:color+'14',borderWidth:1.5,
    pointRadius:0,fill:true,tension:.35,spanGaps:true}]},options:bo});
}
const cLat   = mkLine('cLat',  '#00d4ff','Latency ms');
const cScore = mkLine('cScore','#a855f7','Quality Score');
const cLoss  = new Chart(document.getElementById('cLoss'),{type:'bar',data:{labels:[],
  datasets:[{label:'Loss %',data:[],backgroundColor:[],borderRadius:2}]},options:bo});
const cSpeed = new Chart(document.getElementById('cSpeed'),{type:'line',data:{labels:[],
  datasets:[
    {label:'↑ Upload KB/s',data:[],borderColor:'#ffd700',backgroundColor:'#ffd70012',
     borderWidth:1.5,pointRadius:0,fill:true,tension:.35},
    {label:'↓ Download KB/s',data:[],borderColor:'#00ff88',backgroundColor:'#00ff8812',
     borderWidth:1.5,pointRadius:0,fill:true,tension:.35}
  ]},options:bo});

function el(id){return document.getElementById(id)}
function fmtB(b){const u=['B','KB','MB','GB'];let i=0;while(b>=1024&&i<3){b/=1024;i++}return b.toFixed(1)+' '+u[i]}
function fmtD(s){if(!s&&s!==0)return '--';const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sc=Math.floor(s%60);if(h)return h+'h '+m+'m '+sc+'s';if(m)return m+'m '+sc+'s';return sc+'s'}

function update(d){
  const n=d.net,tr=d.traffic,ss=d.session,devs=d.devices,evts=d.events,mx=d.metrics;
  el('upd').textContent='Updated '+new Date().toLocaleTimeString();

  // Score ring
  const sc=n.score||0,circ=263.9,off=circ-(sc/100)*circ;
  const arc=el('sarc');
  arc.style.strokeDashoffset=off;
  arc.style.stroke=sc>=85?'#00ff88':sc>=70?'#84cc16':sc>=50?'#ffd700':sc>=25?'#ff8c00':'#ff4444';
  el('snum').textContent=sc;
  el('slbl').textContent=n.score_label||'--';
  el('slbl').style.color=sc>=85?'var(--green)':sc>=50?'var(--yellow)':'var(--red)';
  el('sst').textContent='● '+(n.status||'--');

  // Hero
  el('hlat').textContent=n.latency?n.latency.toFixed(1)+' ms':'N/A';
  el('hloss').textContent=(n.loss||0).toFixed(1)+'%';
  el('hup').textContent=ss.up_pct?ss.up_pct.toFixed(1)+'%':'--';

  // Status badge
  const c=SC[n.status]||'#4a6080',sb=el('sbadge');
  sb.style.background=c+'22';sb.style.color=c;
  sb.innerHTML=`<div class="bdot" style="background:${c}"></div>${n.status||'--'}`;

  el('dns').textContent=n.dns_ok?'✓ Resolving':'✗ Failed';
  el('dns').style.color=n.dns_ok?'var(--green)':'var(--red)';
  const flt=(!n.gateway_ok&&!n.internet_ok)?'Local network':
            (n.gateway_ok&&!n.internet_ok)?'ISP Upstream':'None';
  el('fault').textContent=flt;
  el('fault').style.color=flt==='None'?'var(--green)':flt.startsWith('ISP')?'var(--yellow)':'var(--red)';
  el('jitter').textContent=(n.jitter||0).toFixed(1)+' ms';

  // System
  el('lip').textContent=d.local_ip||'--';
  el('pip').textContent=d.public_ip||'--';
  el('gw').textContent=d.gateway||'--';
  el('ifc').textContent=d.iface||'--';

  // Traffic
  el('ups').textContent=(tr.up/1024).toFixed(1)+' KB/s';
  el('dns2').textContent=(tr.dn/1024).toFixed(1)+' KB/s';
  el('tsent').textContent=fmtB(tr.sent);
  el('trecv').textContent=fmtB(tr.recv);

  // Session
  el('rt').textContent=fmtD(ss.total);
  el('ut').textContent=fmtD(ss.uptime);
  el('dt').textContent=fmtD(ss.downtime);
  const p=ss.up_pct||0;
  el('utp').textContent=p.toFixed(2)+'%';
  el('utp').style.color=p>95?'var(--green)':p>80?'var(--yellow)':'var(--red)';
  el('ot').textContent=ss.outages||0;
  el('ot').style.color=ss.outages>0?'var(--red)':'var(--green)';
  el('mtbo').textContent=ss.mtbo?fmtD(ss.mtbo):'--';

  // Targets
  let tr2='';
  for(const[t,r] of Object.entries(n.target_results||{})){
    const lc=r.latency&&r.latency<100?'var(--green)':'var(--red)';
    tr2+=`<div class="ri"><span class="rl" style="font-family:'JetBrains Mono'">${t}</span>
      <span class="rv" style="color:${lc}">${r.latency?r.latency.toFixed(1)+' ms':'Timeout'}</span></div>`;
  }
  el('trows').innerHTML=tr2||'<div style="color:var(--muted);font-size:11px">No data</div>';

  // Devices
  if(devs&&devs.length){
    let dh=`<table><thead><tr><th>IP</th><th>Vendor</th><th>Status</th></tr></thead><tbody>`;
    for(const d2 of devs.slice(0,8)){
      const ac=d2.alive?'var(--green)':'var(--muted)';
      dh+=`<tr><td>${d2.ip}</td><td>${d2.vendor}</td><td style="color:${ac}">${d2.alive?'● Online':'○ Stale'}</td></tr>`;
    }
    dh+=`</tbody></table><div style="font-size:10px;color:var(--muted);margin-top:6px">${devs.length} device(s)</div>`;
    el('devs').innerHTML=dh;
  } else {
    el('devs').innerHTML='<div style="color:var(--muted);font-size:11px">Scanning...</div>';
  }

  // Charts
  const step=Math.max(1,Math.floor(mx.length/30));
  const labels=mx.map((m,i)=>i%step===0?m.ts.slice(11,16):'');
  cLat.data.labels=labels;
  cLat.data.datasets[0].data=mx.map(m=>m.latency);
  cLat.update('none');
  cLoss.data.labels=labels;
  cLoss.data.datasets[0].data=mx.map(m=>m.loss);
  cLoss.data.datasets[0].backgroundColor=mx.map(m=>m.loss>20?'rgba(255,68,68,.7)':m.loss>5?'rgba(255,215,0,.7)':'rgba(0,255,136,.5)');
  cLoss.update('none');
  cSpeed.data.labels=labels;
  cSpeed.data.datasets[0].data=mx.map(m=>(m.up_bps/1024).toFixed(2));
  cSpeed.data.datasets[1].data=mx.map(m=>(m.dn_bps/1024).toFixed(2));
  cSpeed.update('none');
  cScore.data.labels=labels;
  cScore.data.datasets[0].data=mx.map(m=>m.score);
  cScore.update('none');

  // Timeline
  const tl=el('tl');tl.innerHTML='';
  for(const m of mx){
    const s=document.createElement('div');
    s.className='tls';s.style.background=SC[m.status]||'#4a6080';
    s.title=m.ts+' — '+m.status;tl.appendChild(s);
  }

  // Events
  let er='';
  for(const ev of [...evts].reverse().slice(0,12)){
    const ec=EC[ev.event]||'#4a6080';
    er+=`<tr><td>${ev.timestamp}</td>
      <td><span class="eb" style="background:${ec}">${ev.event}</span></td>
      <td>${ev.detail}</td><td>${ev.duration_sec||'—'}</td></tr>`;
  }
  el('evrows').innerHTML=er||'<tr><td colspan="4" style="color:var(--muted)">No events yet</td></tr>';
}

// Auto-reconnect polling
let delay=2000,timer=null;
function poll(){
  fetch('/data')
    .then(r=>{if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
    .then(d=>{update(d);delay=2000;timer=setTimeout(poll,2000);})
    .catch(()=>{
      el('upd').textContent='Reconnecting in '+(delay/1000).toFixed(0)+'s...';
      timer=setTimeout(poll,delay);
      delay=Math.min(delay*1.5,15000);
    });
}
poll();
</script>
</body>
</html>"""


# ── Flask App ─────────────────────────────────────────────────────────────────
def build_flask_app(state):
    app = Flask(__name__)
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.logger.disabled = True

    @app.route("/")
    def index():
        return render_template_string(WEB_HTML)

    @app.route("/data")
    def data():
        with state["lock"]:
            payload = {
                "net":       state.get("net") or {},
                "traffic":   state.get("traffic") or {"up":0,"dn":0,"sent":0,"recv":0},
                "session":   state.get("session_summary") or {},
                "devices":   state.get("devices") or [],
                "events":    state.get("events") or [],
                "metrics":   state.get("metrics") or [],
                "local_ip":  state.get("local_ip", "--"),
                "public_ip": state.get("public_ip", "--"),
                "gateway":   state.get("gateway", "--"),
                "iface":     state.get("iface", "--"),
            }
        return Response(json.dumps(payload), mimetype="application/json")

    return app


# ── HTML Report (generated on exit) ──────────────────────────────────────────
def generate_report(state, args):
    metrics = state.get("metrics", [])
    events  = state.get("events",  [])
    ss      = state.get("session_summary", {})

    if not metrics:
        return False

    ts    = [m["ts"]    for m in metrics]
    lats  = [m["latency"] for m in metrics]
    losses= [m["loss"]  for m in metrics]
    scores= [m["score"] for m in metrics]
    ups   = [round(m["up_bps"]/1024, 2) for m in metrics]
    dns   = [round(m["dn_bps"]/1024, 2) for m in metrics]

    SC = {"ONLINE":"#00ff88","DEGRADED":"#ffd700",
          "ISP_FAILURE":"#ff8c00","OFFLINE":"#ff4444","UNKNOWN":"#4a6080"}
    EC = {"OUTAGE_START":"#ff4444","RECOVERY":"#00ff88",
          "STATUS_CHANGE":"#ffd700","SESSION_START":"#00d4ff"}

    sd = [{"ts":m["ts"],"status":m["status"],"color":SC.get(m["status"],"#4a6080")}
          for m in metrics]

    valid_lats = [x for x in lats if x is not None]
    avg_lat    = statistics.mean(valid_lats) if valid_lats else 0
    max_lat    = max(valid_lats) if valid_lats else 0
    avg_loss   = statistics.mean(losses) if losses else 0
    avg_score  = statistics.mean(scores) if scores else 0

    erows = ""
    for ev in events:
        c = EC.get(ev["event"], "#4a6080")
        erows += (f"<tr><td>{ev['timestamp']}</td>"
                  f"<td><span class='eb' style='background:{c}'>{ev['event']}</span></td>"
                  f"<td>{ev['detail']}</td>"
                  f"<td>{ev.get('duration_sec','—')}</td></tr>")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PulseNet Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{{--bg:#080d14;--surf:#0f1724;--bdr:#1e2d40;--text:#e2e8f0;--muted:#4a6080;
  --cyan:#00d4ff;--green:#00ff88;--yellow:#ffd700;--red:#ff4444;--purple:#a855f7}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Syne',sans-serif}}
body::before{{content:'';position:fixed;inset:0;
  background:radial-gradient(ellipse at 20% 20%,#00d4ff08,transparent 50%),
             radial-gradient(ellipse at 80% 80%,#00ff8806,transparent 50%);pointer-events:none}}
header{{padding:24px 44px;border-bottom:1px solid var(--bdr);display:flex;
  justify-content:space-between;align-items:center}}
.logo{{font-size:20px;font-weight:800;color:var(--cyan)}}
.logo span{{color:var(--muted);font-weight:400;font-size:13px;margin-left:8px}}
.meta{{text-align:right;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted)}}
.meta strong{{color:var(--text);display:block;font-size:13px}}
.wrap{{max-width:1300px;margin:0 auto;padding:28px 44px}}
.sec{{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);
  font-weight:600;padding-bottom:8px;border-bottom:1px solid var(--bdr);margin-bottom:14px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px}}
.card{{background:var(--surf);border:1px solid var(--bdr);border-radius:10px;padding:18px;
  position:relative;overflow:hidden}}
.card::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--ac,var(--cyan))}}
.cl{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:7px;font-weight:600}}
.cv{{font-family:'JetBrains Mono',monospace;font-size:24px;font-weight:700;color:var(--ac,var(--cyan))}}
.cs{{font-size:11px;color:var(--muted);margin-top:3px}}
.cg{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}}
.cw{{background:var(--surf);border:1px solid var(--bdr);border-radius:10px;padding:20px}}
.cw.s2{{grid-column:1/-1}}
.cht{{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);
  font-weight:600;margin-bottom:14px}}
.tl{{display:flex;height:22px;border-radius:5px;overflow:hidden;gap:1px;margin-bottom:8px}}
.tls{{flex:1;min-width:2px}}
.leg{{display:flex;gap:14px;font-size:10px;color:var(--muted)}}
table{{width:100%;border-collapse:collapse;font-size:11px}}
th{{text-align:left;padding:7px 10px;color:var(--muted);font-size:9px;text-transform:uppercase;
  letter-spacing:.5px;border-bottom:1px solid var(--bdr);font-weight:600}}
td{{padding:7px 10px;border-bottom:1px solid var(--bdr);font-family:'JetBrains Mono',monospace;font-size:11px}}
tr:last-child td{{border-bottom:none}}
.eb{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;
  font-weight:700;color:#fff;font-family:'JetBrains Mono',monospace}}
footer{{text-align:center;padding:24px;color:var(--muted);font-size:10px;
  border-top:1px solid var(--bdr);margin-top:16px;font-family:'JetBrains Mono',monospace}}
</style>
</head>
<body>
<header>
  <div><div class="logo">◈ PulseNet <span>Session Report v3.0</span></div></div>
  <div class="meta"><strong>{datetime.now().strftime('%A, %B %d %Y')}</strong>
    Generated {datetime.now().strftime('%H:%M:%S')}</div>
</header>
<div class="wrap">
<div class="sec">Summary</div>
<div class="cards">
  <div class="card" style="--ac:{'var(--green)' if ss.get('up_pct',0)>95 else 'var(--yellow)' if ss.get('up_pct',0)>80 else 'var(--red)'}">
    <div class="cl">Uptime</div><div class="cv">{ss.get('up_pct',0):.1f}<span style="font-size:13px">%</span></div>
    <div class="cs">{fmt_dur(ss.get('uptime',0))} online</div></div>
  <div class="card" style="--ac:var(--cyan)">
    <div class="cl">Runtime</div><div class="cv" style="font-size:16px">{fmt_dur(ss.get('total',0))}</div>
    <div class="cs">{len(metrics)} samples</div></div>
  <div class="card" style="--ac:{'var(--green)' if avg_lat<80 else 'var(--yellow)' if avg_lat<200 else 'var(--red)'}">
    <div class="cl">Avg Latency</div><div class="cv">{avg_lat:.1f}<span style="font-size:13px;color:var(--muted)">ms</span></div>
    <div class="cs">Peak {max_lat:.1f} ms</div></div>
  <div class="card" style="--ac:{'var(--green)' if avg_loss==0 else 'var(--yellow)' if avg_loss<10 else 'var(--red)'}">
    <div class="cl">Avg Packet Loss</div><div class="cv">{avg_loss:.1f}<span style="font-size:13px;color:var(--muted)">%</span></div></div>
  <div class="card" style="--ac:{'var(--red)' if ss.get('outages',0)>0 else 'var(--green)'}">
    <div class="cl">Outages</div><div class="cv">{ss.get('outages',0)}</div>
    <div class="cs">{fmt_dur(ss.get('downtime',0))} downtime</div></div>
  <div class="card" style="--ac:var(--purple)">
    <div class="cl">Avg Quality Score</div>
    <div class="cv">{avg_score:.0f}<span style="font-size:13px;color:var(--muted)">/100</span></div>
    <div class="cs">{score_label(avg_score)}</div></div>
</div>

<div class="sec">Connectivity Timeline</div>
<div class="cw s2" style="margin-bottom:16px">
  <div class="tl" id="tl"></div>
  <div class="leg">
    <span><span style="color:#00ff88">●</span> Online</span>
    <span><span style="color:#ffd700">●</span> Degraded</span>
    <span><span style="color:#ff8c00">●</span> ISP Failure</span>
    <span><span style="color:#ff4444">●</span> Offline</span>
  </div>
</div>

<div class="sec">Charts</div>
<div class="cg">
  <div class="cw s2"><div class="cht">Latency (ms)</div><canvas id="cLat" height="65"></canvas></div>
  <div class="cw"><div class="cht">Packet Loss (%)</div><canvas id="cLoss" height="120"></canvas></div>
  <div class="cw"><div class="cht">Quality Score</div><canvas id="cScore" height="120"></canvas></div>
  <div class="cw s2"><div class="cht">Network Speed (KB/s)</div><canvas id="cSpeed" height="65"></canvas></div>
</div>

<div class="sec">Event Log</div>
<div class="cw" style="margin-bottom:0">
  <table><thead><tr><th>Timestamp</th><th>Event</th><th>Detail</th><th>Duration</th></tr></thead>
  <tbody>{erows or "<tr><td colspan='4' style='color:var(--muted)'>No events recorded</td></tr>"}</tbody></table>
</div>
</div>
<footer>◈ PulseNet v3.0 &nbsp;·&nbsp; {len(metrics)} data points &nbsp;·&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
<script>
const ts={json.dumps(ts)},lats={json.dumps(lats)},losses={json.dumps(losses)},
      scores={json.dumps(scores)},ups={json.dumps(ups)},dns={json.dumps(dns)},
      sd={json.dumps(sd)};
const step=Math.max(1,Math.floor(ts.length/25));
const labels=ts.map((t,i)=>i%step===0?t.slice(11,16):'');
const gc='rgba(255,255,255,0.04)';
const bo={{responsive:true,animation:{{duration:600}},
  plugins:{{legend:{{labels:{{color:'#4a6080',font:{{size:10}}}}}}}},
  scales:{{x:{{ticks:{{color:'#4a6080',maxRotation:0,font:{{size:9}}}},grid:{{color:gc}}}},
           y:{{ticks:{{color:'#4a6080',font:{{size:9}}}},grid:{{color:gc}}}}}}}};
new Chart(document.getElementById('cLat'),{{type:'line',data:{{labels,datasets:[{{label:'Latency ms',
  data:lats,borderColor:'#00d4ff',backgroundColor:'#00d4ff12',borderWidth:1.5,
  pointRadius:0,fill:true,tension:.35,spanGaps:true}}]}},options:bo}});
new Chart(document.getElementById('cLoss'),{{type:'bar',data:{{labels,datasets:[{{label:'Loss %',
  data:losses,backgroundColor:losses.map(v=>v>20?'rgba(255,68,68,.7)':v>5?'rgba(255,215,0,.7)':'rgba(0,255,136,.5)'),
  borderRadius:2}}]}},options:bo}});
new Chart(document.getElementById('cScore'),{{type:'line',data:{{labels,datasets:[{{label:'Score',
  data:scores,borderColor:'#a855f7',backgroundColor:'#a855f712',borderWidth:1.5,
  pointRadius:0,fill:true,tension:.35}}]}},options:bo}});
new Chart(document.getElementById('cSpeed'),{{type:'line',data:{{labels,datasets:[
  {{label:'↑ Upload',data:ups,borderColor:'#ffd700',backgroundColor:'#ffd70012',borderWidth:1.5,pointRadius:0,fill:true,tension:.35}},
  {{label:'↓ Download',data:dns,borderColor:'#00ff88',backgroundColor:'#00ff8812',borderWidth:1.5,pointRadius:0,fill:true,tension:.35}}
]}},options:bo}});
const tl=document.getElementById('tl');
sd.forEach(d=>{{const s=document.createElement('div');s.className='tls';
  s.style.background=d.color;s.title=d.ts+' — '+d.status;tl.appendChild(s)}});
</script>
</body>
</html>"""

    try:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(html)
        return True
    except Exception as e:
        print(f"Report error: {e}")
        return False


# ── Entry Point ───────────────────────────────────────────────────────────────
def main():
    global NO_COLOR
    args = parse_args()
    if args.no_color: NO_COLOR = True
    if IS_WIN: os.system("")  # enable ANSI on Windows

    print(cl("\n  ◈ PulseNet Monitoring Engine v3.0", A.CYN, A.BOLD))
    print(cl("  Initialising...\n", A.GRY))

    # Warnings
    no_priv = False
    if not args.no_arp and not is_root():
        print(cl("  ⚠  Run as admin/sudo for full ARP device discovery.\n"
                 "     Continuing with limited scan capability.\n", A.YLW))
        no_priv = True

    if not PSUTIL_OK:
        print(cl("  ⚠  psutil not found — traffic monitoring disabled.\n"
                 "     Install: python -m pip install psutil\n", A.YLW))

    if not FLASK_OK and not args.no_web:
        print(cl("  ⚠  Flask not found — web dashboard disabled.\n"
                 "     Install: python -m pip install flask\n", A.YLW))

    # Detect network info
    iface, local_ip = get_primary_interface()
    gateway         = get_gateway()
    subnet          = get_local_subnet(local_ip)

    print(cl(f"  Interface : {iface or 'Unknown'}", A.GRY))
    print(cl(f"  Local IP  : {local_ip}", A.GRY))
    print(cl(f"  Subnet    : {subnet or 'Unknown'}", A.GRY))
    print(cl(f"  Gateway   : {gateway}", A.GRY))
    print(cl(f"  Targets   : {', '.join(args.targets)}", A.GRY))
    print(cl("  Public IP : fetching...", A.GRY), end="", flush=True)
    public_ip = get_public_ip()
    print(cl(f"\r  Public IP : {public_ip}", A.MGT))

    if not args.no_web and FLASK_OK:
        print(cl(f"  Web dash  : http://localhost:{args.web_port}  "
                 f"(also accessible on your network)", A.CYN))
    print(cl(f"  Report    : {args.report}\n", A.GRY))
    print(cl("  Starting in 2 seconds...", A.GRY))
    time.sleep(2)

    # Shared state dict for web server
    state = {
        "lock": threading.Lock(),
        "net": {}, "traffic": {"up":0,"dn":0,"sent":0,"recv":0},
        "session_summary": {}, "devices": [], "events": [], "metrics": [],
        "local_ip": local_ip, "public_ip": public_ip,
        "gateway": gateway, "iface": iface,
    }

    # Initialise components
    event_log   = EventLog(maxlen=500, max_age=args.max_age)
    metrics_st  = MetricsStore(maxlen=args.history, max_age=args.max_age)
    session     = Session()
    traffic_mon = TrafficMonitor(iface=iface)
    scanner     = ARPScanner(enabled=not args.no_arp, local_ip=local_ip)
    lat_hist    = deque(maxlen=60)
    dashboard   = TerminalDashboard()
    pauser      = PauseController()

    if not args.no_arp:
        scanner.start(interval=args.arp_interval)

    # Start Flask web server
    if not args.no_web and FLASK_OK:
        flask_app = build_flask_app(state)
        def start_flask():
            try:
                flask_app.run(
                    host="0.0.0.0", port=args.web_port,
                    debug=False, use_reloader=False)
            except Exception as e:
                print(cl(f"\n  ⚠  Web dashboard failed to start: {e}", A.RED))
        threading.Thread(target=start_flask, daemon=True).start()
        time.sleep(0.5)  # Give Flask time to start and potentially fail

    # Public IP refresh every 5 minutes
    def refresh_public_ip():
        while True:
            time.sleep(300)
            ip = get_public_ip()
            with state["lock"]:
                state["public_ip"] = ip
    threading.Thread(target=refresh_public_ip, daemon=True).start()

    # Start pause listener
    pauser.start()

    # Clear terminal
    sys.stdout.write(A.CLR + A.HIDE)
    sys.stdout.flush()

    # ── Main Loop ─────────────────────────────────────────────────────────────
    try:
        while True:
            if pauser.is_paused():
                time.sleep(0.2)
                continue

            net = get_network_status(gateway, args.targets, args.ping_count)
            if net["latency"]:
                lat_hist.append(net["latency"])

            traffic_mon.update()
            tr = traffic_mon.snap()

            session.update(net["status"], event_log)
            ss = session.summary()

            metrics_st.add(net, tr)

            devices, last_scan = scanner.get()

            # Sync shared state
            with state["lock"]:
                state["net"]             = net
                state["traffic"]         = tr
                state["session_summary"] = ss
                state["devices"]         = devices
                state["events"]          = event_log.all()
                state["metrics"]         = metrics_st.all()

            # Draw terminal dashboard
            dashboard.draw(
                net, tr, devices, last_scan,
                local_ip, state["public_ip"], gateway, iface,
                session, event_log, metrics_st,
                lat_hist, pauser.is_paused(), no_priv, args
            )

            time.sleep(args.interval)

    except KeyboardInterrupt:
        pauser.stop()
        scanner.stop()
        sys.stdout.write(A.SHOW + "\n")
        sys.stdout.flush()

        with state["lock"]:
            state["session_summary"] = session.summary()

        ss = session.summary()
        print(cl("\n  ◈ PulseNet — Session Summary", A.CYN, A.BOLD))
        print(cl("  " + "═" * 50, A.CYN))

        def row(l, v, c=A.WHT):
            print(f"  {cl(l+':', A.GRY):<32} {cl(v, c)}")

        row("Total Runtime",     fmt_dur(ss["total"]))
        row("Uptime",            fmt_dur(ss["uptime"]),   A.GRN)
        row("Downtime",          fmt_dur(ss["downtime"]),
            A.RED if ss["downtime"] > 0 else A.GRY)
        row("Uptime %",          f"{ss['up_pct']:.2f}%",
            A.GRN if ss["up_pct"] > 95 else A.YLW)
        row("Total Outages",     str(ss["outages"]),
            A.RED if ss["outages"] > 0 else A.GRN)
        if ss["mtbo"]:
            row("Avg Outage Duration", fmt_dur(ss["mtbo"]), A.YLW)

        print(cl("\n  Generating HTML report...", A.GRY))
        ok = generate_report(state, args)
        if ok:
            print(cl(f"  Saved: {args.report}", A.GRN))
            print(cl("  Open in your browser to view all charts.\n", A.GRY))
        else:
            print(cl("  Not enough data to generate report.\n", A.YLW))

        print(cl("  Thank you for using PulseNet.\n", A.CYN))


if __name__ == "__main__":
    main()
