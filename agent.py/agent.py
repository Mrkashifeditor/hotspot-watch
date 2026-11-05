#!/usr/bin/env python3
"""
hotspot-watch — agent.py
Local reporter for Ruijie RG-EW300N (192.168.111.1).

What it does: polls the router / a gateway / a CSV export, scores each
MAC for hotspot-sharing suspicion, and writes a REPORT. It never blocks
anything. The user blocks suspects himself in the Reyee app.

What it CANNOT do (honest limits):
  - From the EW300N alone it cannot see behind a phone's NAT. The router
    only sees the phone's MAC/IP. Traffic spikes are SUSPICION, not proof.
  - Only gateway mode (Mode B) can PROVE hotspot sharing, via TTL 63/127.
  - 192.168.111.1 is a private LAN IP. No internet server can reach it.
    This agent must run ON the user's LAN (Pi / PC on the same Wi-Fi/LAN).
  - Detection is NOT 100%. A technical user can set TTL 65 on a laptop
    and bypass TTL checks.

Dependencies: Python 3.9+ stdlib only for core. `requests` is optional
(used for the router probe if installed). `scapy` is optional (gateway
TTL sniffing only; tcpdump parsing works without it).

Config: config.yaml (copy from config.yaml.example) + .env
  (copy from .env.example; never commit .env — see .gitignore).
  Router eWeb password comes ONLY from .env ROUTER_PASSWORD, never
  from code, chat, or git history.

Usage:
  python3 agent.py --once                 # one Mode-A poll + report
  python3 agent.py --once --csv clients.csv
  python3 agent.py --once --gateway --pcap capture.pcap
  python3 agent.py --report               # regenerate report from history
  python3 agent.py                         # loop every poll_interval_minutes
  python3 report.py                       # same as --report
"""
import argparse
import csv
import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
HISTORY_FILE = DATA_DIR / "history.jsonl"
DEBUG_DIR = DATA_DIR / "debug"

DEFAULTS = {
    "router_host": "192.168.111.1",
    "router_scheme": "https",
    "router_password_env": "ROUTER_PASSWORD",
    "poll_interval_minutes": 5,
    "baseline_days": 7,
    "phone_down_threshold_mb_1h": 500,
    "spike_multiplier": 3.0,
    "gateway_mode": False,
    "report_timezone": "Asia/Karachi",
}

# ---------------------------------------------------------------- .env / config

def load_dotenv(path=BASE_DIR / ".env"):
    """Load KEY=VALUE lines into os.environ (does not overwrite existing)."""
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        out[k] = v
        os.environ.setdefault(k, v)
    return out


def _simple_yaml_load(path):
    """Minimal YAML subset parser (flat keys + one level of nesting).

    Tries PyYAML first if installed; otherwise parses `key: value` lines.
    This keeps the core stdlib-only.
    """
    try:
        import yaml  # type: ignore
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except ImportError:
        pass
    cfg = {}
    current_section = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        if not raw.startswith((" ", "\t")) and raw.rstrip().endswith(":"):
            current_section = raw.strip()[:-1]
            cfg[current_section] = {}
            continue
        m = re.match(r"^\s*([^:#]+):\s*(.+?)\s*$", raw)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()
        # coerce types
        if val.lower() in ("true", "false"):
            val = val.lower() == "true"
        else:
            try:
                val = int(val)
            except ValueError:
                try:
                    val = float(val)
                except ValueError:
                    val = val.strip('"').strip("'")
        if current_section:
            cfg[current_section][key] = val
        else:
            cfg[key] = val
    return cfg


def load_config(path=None):
    cfg = dict(DEFAULTS)
    p = Path(path) if path else BASE_DIR / "config.yaml"
    if p.exists():
        raw = _simple_yaml_load(p)
        # flatten one level: router: {host: ...} -> router_host
        for k, v in raw.items():
            if isinstance(v, dict):
                for sk, sv in v.items():
                    cfg[f"{k}_{sk}"] = sv
            else:
                cfg[k] = v
    # env overrides (explicit, no secrets in config file)
    for key in ("ROUTER_HOST", "ROUTER_SCHEME"):
        if os.getenv(key):
            cfg[key.lower()] = os.getenv(key)
    return cfg


# ---------------------------------------------------------------- history / baseline

def load_history(days=7):
    """Return {mac_lower: [down_mb_1h, ...]} for the last `days` days."""
    if not HISTORY_FILE.exists():
        return {}
    cutoff = time.time() - days * 86400
    by_mac = {}
    for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("ts_epoch", 0) < cutoff:
            continue
        mac = str(rec.get("mac", "")).lower()
        if mac:
            by_mac.setdefault(mac, []).append(float(rec.get("down_mb", 0) or 0))
    return by_mac


def baseline_median(by_mac, mac):
    vals = by_mac.get(str(mac).lower(), [])
    if len(vals) < 3:
        return None  # not enough history — do not invent a baseline
    return statistics.median(vals)


def append_history(records, ts_epoch, source):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with HISTORY_FILE.open("a", encoding="utf-8") as f:
        for r in records:
            rec = dict(r)
            rec["ts_epoch"] = ts_epoch
            rec["source"] = source
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- scoring (pure, testable)

def score_client(client, baseline=None, ttl_seen=None, os_fingerprints=None,
                 spike_multiplier=3.0, phone_threshold_mb=500):
    """Score one client. Returns dict with level, score, reasons.

    Levels:
      NORMAL  — no strong signal
      SUSPECT — spike / volume / mixed-OS signal (NOT proof)
      PROOF   — TTL 63/127 seen in gateway mode ONLY. This is the only
                level that counts as proof, and only in gateway mode.
    """
    mac = str(client.get("mac", "")).upper()
    down = float(client.get("down_mb", 0) or 0)
    up = float(client.get("up_mb", 0) or 0)
    device_type = str(client.get("device_type", "phone")).lower()
    reasons, score = [], 0

    if baseline is not None and baseline > 0:
        ratio = down / baseline
        if ratio >= spike_multiplier:
            score += 50
            reasons.append(
                f"Traffic spike: {down:.0f} MB in 1h vs 7-day median "
                f"{baseline:.0f} MB ({ratio:.1f}x baseline)"
            )
    if device_type == "phone" and down > phone_threshold_mb:
        score += 50
        reasons.append(
            f"Phone-only MAC used {down:.0f} MB down in 1h "
            f"(threshold {phone_threshold_mb} MB)"
        )
    if ttl_seen in (63, 127):
        score += 100
        reasons.append(
            f"TTL {ttl_seen} seen in gateway mode — packet passed through "
            f"one extra hop (phone hotspot NAT). Android/iOS TTL 64 -> 63, "
            f"Windows 128 -> 127."
        )
    fps = list(os_fingerprints or [])
    oss = {str(x).lower() for x in fps}
    if len(oss) > 1:
        score += 50
        reasons.append(
            f"Mixed OS fingerprints from one IP ({', '.join(sorted(oss))}) — "
            f"one phone should not look like two operating systems at once"
        )

    if ttl_seen in (63, 127):
        level = "PROOF"
    elif score >= 50:
        level = "SUSPECT"
    else:
        level = "NORMAL"

    return {
        "mac": mac,
        "ip": str(client.get("ip", "")),
        "name": str(client.get("hostname", client.get("name", ""))),
        "device_type": device_type,
        "up_mb": up,
        "down_mb": down,
        "baseline_mb": baseline,
        "ttl_seen": ttl_seen,
        "os_fingerprints": fps,
        "score": score,
        "level": level,
        "reasons": reasons,
    }


# ---------------------------------------------------------------- Mode C: CSV

def read_csv_clients(path):
    """CSV columns: mac,ip,hostname,up_mb,down_mb[,device_type,ttl_seen,os_fingerprints].

    os_fingerprints is ';'-separated, e.g. 'ios;windows'.
    """
    clients = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if not row.get("mac"):
                continue
            ttl = row.get("ttl_seen") or ""
            try:
                ttl = int(ttl) if str(ttl).strip() else None
            except ValueError:
                ttl = None
            fps = [s.strip() for s in str(row.get("os_fingerprints", "")).split(";") if s.strip()]
            clients.append({
                "mac": row["mac"].strip(),
                "ip": (row.get("ip") or "").strip(),
                "hostname": (row.get("hostname") or "").strip(),
                "up_mb": float(row.get("up_mb") or 0),
                "down_mb": float(row.get("down_mb") or 0),
                "device_type": (row.get("device_type") or "phone").strip().lower(),
                "ttl_seen": ttl,
                "os_fingerprints": fps,
            })
    return clients


# ---------------------------------------------------------------- Mode B: gateway TTL

TTL_RE = re.compile(r"ttl[= ](\d+)", re.IGNORECASE)


def parse_tcpdump_line(line):
    """Extract (src_ip, ttl) from one tcpdump -v line, or None."""
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)\.\d+ > .*ttl (\d+)", line, re.IGNORECASE)
    if m:
        return m.group(1), int(m.group(2))
    m2 = TTL_RE.search(line)
    if m2:
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        return (ip_m.group(1) if ip_m else ""), int(m2.group(1))
    return None


def ttl_evidence_from_pcap_text(text):
    """Return {src_ip: set(ttls)} from tcpdump -v output text."""
    out = {}
    for line in text.splitlines():
        parsed = parse_tcpdump_line(line)
        if parsed:
            ip, ttl = parsed
            out.setdefault(ip, set()).add(ttl)
    return out


def sniff_ttl_via_tcpdump(interface="eth0", seconds=60):
    """Run tcpdump briefly and return {ip: set(ttls)}. Requires tcpdump."""
    try:
        proc = subprocess.run(
            ["tcpdump", "-nn", "-v", "-i", interface, "-c", "500"],
            capture_output=True, text=True, timeout=seconds + 10,
        )
        return ttl_evidence_from_pcap_text(proc.stdout + proc.stderr)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"[gateway] tcpdump unavailable/failed: {e}", file=sys.stderr)
        return {}


def sniff_ttl_via_scapy(interface=None, seconds=60):
    """Optional scapy sniff. Returns {ip: set(ttls)} or {} if scapy missing."""
    try:
        from scapy.all import sniff, IP  # type: ignore
    except ImportError:
        return {}
    seen = {}

    def _cb(pkt):
        if IP in pkt:
            seen.setdefault(pkt[IP].src, set()).add(int(pkt[IP].ttl))

    sniff(iface=interface, prn=_cb, timeout=seconds, store=False)
    return seen


# ---------------------------------------------------------------- Mode A: router eWeb probe (pluggable, honest)

# Candidate eWeb client-list endpoints. These are PROBES, not a guaranteed
# API — Ruijie does not publish this API and it varies by firmware.
# If none match, the collector logs the raw response and tells the user
# exactly which config value to set. It NEVER fabricates client data.
CANDIDATE_CLIENT_URLS = [
    "/cgi-bin/luci/api/client/list",
    "/api/client/list",
    "/cgi-bin/api/client/list",
    "/api/v1/clients",
    "/eweb/api/client/list",
    "/cgi-bin/luci/rpc/client/list",
]

CANDIDATE_LOGIN_URLS = [
    "/cgi-bin/luci/rpc/auth",
    "/api/login",
    "/cgi-bin/api/login",
]


def _http_get(session, url, timeout=10):
    try:
        import requests
        r = session.get(url, timeout=timeout, verify=False)
        return r.status_code, r.text[:4000]
    except Exception as e:  # requests missing or network error
        return None, f"request failed: {e}"


def probe_router(cfg, save_debug=True):
    """Try to fetch the Online Clients list from the router eWeb.

    Returns (clients, status_dict). clients is [] on failure — with a
    clear status explaining why, and a debug file if save_debug.
    """
    import urllib3  # noqa: F401  (only to silence warnings if present)
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    host = cfg["router_host"]
    scheme = cfg.get("router_scheme", "https")
    base = f"{scheme}://{host}"
    password = os.getenv(str(cfg.get("router_password_env", "ROUTER_PASSWORD")), "")
    custom_url = cfg.get("router_client_list_url") or cfg.get("client_list_url")

    attempts = []
    session = None
    try:
        import requests
        session = requests.Session()
    except ImportError:
        session = None

    # If the user supplied an explicit endpoint, try only that one first.
    urls = [custom_url] if custom_url else CANDIDATE_CLIENT_URLS
    # Resolve relative custom URL against base
    urls = [u if u.startswith("http") else base + u for u in urls]

    clients = []
    for url in urls:
        if session is not None:
            status, body = _http_get(session, url)
        else:
            # stdlib fallback: urllib with cookie jar
            import urllib.request, http.cookiejar
            cj = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cj))
            try:
                import ssl
                ctx = ssl._create_unverified_context()
                with opener.open(url, timeout=10, context=ctx) as r:
                    status, body = r.status, r.read().decode("utf-8", "ignore")[:4000]
            except Exception as e:
                status, body = None, f"request failed: {e}"
        attempts.append({"url": url, "status": status,
                         "body_snippet": (body or "")[:500]})
        if status == 200 and body:
            parsed = _parse_client_body(body)
            if parsed:
                clients = parsed
                break

    status_info = {
        "mode": "router",
        "router": base,
        "password_supplied": bool(password),
        "requests_available": session is not None,
        "attempts": attempts,
        "clients_found": len(clients),
        "note": (
            "Ruijie eWeb AJAX endpoints are undocumented and vary by "
            "firmware. If no endpoint matched, set router_client_list_url "
            "in config.yaml to the working eWeb URL (find it in your "
            "browser DevTools > Network while opening Clients in eWeb), "
            "or use Mode C (CSV export) instead. No client data was invented."
            if not clients else "Client list parsed from router response."
        ),
    }
    if save_debug and not clients:
        DEBUG_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        (DEBUG_DIR / f"router-probe-{ts}.json").write_text(
            json.dumps(status_info, indent=2, ensure_ascii=False),
            encoding="utf-8")
        status_info["debug_file"] = str(DEBUG_DIR / f"router-probe-{ts}.json")
    return clients, status_info


def _parse_client_body(body):
    """Parse a router response body into client dicts, or [] if not a list.

    Accepts JSON with any of these shapes:
      {"clients": [...]}, {"data": [...]}, {"list": [...]}, or a bare [...]
    Each item needs mac + (ip/hostname/up/down if present).
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []
    items = None
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("clients", "data", "list", "online_clients", "result"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
    if not items:
        return []
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        mac = it.get("mac") or it.get("MAC") or it.get("macAddress")
        if not mac:
            continue
        out.append({
            "mac": str(mac),
            "ip": str(it.get("ip") or it.get("ipAddress") or ""),
            "hostname": str(it.get("hostname") or it.get("name") or it.get("hostName") or ""),
            "up_mb": float(it.get("up_mb") or it.get("upload") or it.get("tx") or 0),
            "down_mb": float(it.get("down_mb") or it.get("download") or it.get("rx") or 0),
            "device_type": str(it.get("device_type") or it.get("type") or "phone").lower(),
            "ttl_seen": None,
            "os_fingerprints": [],
        })
    return out


# ---------------------------------------------------------------- reporting

def generate_report(scored, ts=None, source="router", probe_status=None):
    """Write reports/report-YYYY-MM-DD-HHMM.md + reports/latest.json."""
    ts = ts or datetime.now(timezone.utc)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = ts.strftime("%Y-%m-%d-%H%M")
    suspects = [s for s in scored if s["level"] in ("SUSPECT", "PROOF")]
    normals = [s for s in scored if s["level"] == "NORMAL"]

    lines = []
    lines.append(f"# hotspot-watch report — {stamp} UTC")
    lines.append("")
    lines.append(f"Source: **{source}** | Clients checked: **{len(scored)}** | "
                 f"Flagged: **{len(suspects)}**")
    lines.append("")
    lines.append("> This is a REPORT, not a block. Detection is not 100%. "
                 "SUSPECT means 'worth checking', PROOF (TTL only, gateway "
                 "mode) means a packet passed through an extra hop. "
                 "Block suspects yourself in the Reyee app.")
    lines.append("")
    if probe_status and not scored:
        lines.append("## Router probe status")
        lines.append("")
        lines.append(f"- Router: `{probe_status.get('router')}`")
        lines.append(f"- Password supplied via .env: "
                     f"{'yes' if probe_status.get('password_supplied') else 'NO — set ROUTER_PASSWORD in .env'}")
        lines.append(f"- Attempts: {len(probe_status.get('attempts', []))}")
        for a in probe_status.get("attempts", []):
            lines.append(f"  - `{a['url']}` → HTTP {a['status']}")
        lines.append(f"- Note: {probe_status.get('note')}")
        if probe_status.get("debug_file"):
            lines.append(f"- Debug file: `{probe_status['debug_file']}`")
        lines.append("")
    if suspects:
        lines.append("## Flagged — check these first")
        lines.append("")
        lines.append("| MAC | IP | Name | Down 1h | Baseline (7d median) | Level | Score | Reason |")
        lines.append("|---|---|---|---:|---:|---|---|---|")
        for s in sorted(suspects, key=lambda x: -x["score"]):
            base = f"{s['baseline_mb']:.0f} MB" if s['baseline_mb'] is not None else "n/a (too little history)"
            reason = "; ".join(s["reasons"]) if s["reasons"] else "—"
            lines.append(f"| `{s['mac']}` | {s['ip']} | {s['name']} | "
                         f"{s['down_mb']:.0f} MB | {base} | **{s['level']}** | "
                         f"{s['score']} | {reason} |")
        lines.append("")
        lines.append("### How to block (Reyee app, you do this — the agent never blocks)")
        lines.append("")
        lines.append("1. Open the Reyee app → **Clients**")
        lines.append("2. Tap the flagged device (match by MAC above)")
        lines.append("3. Tap **Block** / add to blacklist")
        lines.append("4. If the user complains the internet stopped, that confirms "
                     "they were the sharer — unblock only if you choose to.")
        lines.append("")
    else:
        lines.append("## Flagged — none")
        lines.append("")
        lines.append("No client crossed the SUSPECT threshold in this run.")
        lines.append("")
    if normals:
        lines.append("## Normal (not flagged)")
        lines.append("")
        lines.append("| MAC | IP | Name | Down 1h |")
        lines.append("|---|---|---|---:|")
        for s in normals:
            lines.append(f"| `{s['mac']}` | {s['ip']} | {s['name']} | {s['down_mb']:.0f} MB |")
        lines.append("")

    md_path = REPORTS_DIR / f"report-{stamp}.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    latest = {
        "generated_utc": ts.isoformat(),
        "source": source,
        "clients_checked": len(scored),
        "flagged": len(suspects),
        "scored": scored,
        "probe_status": probe_status,
    }
    (REPORTS_DIR / "latest.json").write_text(
        json.dumps(latest, indent=2, ensure_ascii=False), encoding="utf-8")
    return md_path


def regenerate_report_from_history():
    """Rebuild the latest report from data/history.jsonl (last run per MAC)."""
    if not HISTORY_FILE.exists():
        print("No history yet — run agent.py --once first.")
        return None
    by_mac = {}
    for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        by_mac[str(rec.get("mac", "")).lower()] = rec
    cfg = load_config()
    hist = load_history(days=cfg.get("baseline_days", 7))
    scored = []
    for rec in by_mac.values():
        scored.append(score_client(
            rec,
            baseline=baseline_median(hist, rec.get("mac", "")),
            ttl_seen=rec.get("ttl_seen"),
            os_fingerprints=rec.get("os_fingerprints") or [],
            spike_multiplier=float(cfg.get("spike_multiplier", 3.0)),
            phone_threshold_mb=float(cfg.get("phone_down_threshold_mb_1h", 500)),
        ))
    return generate_report(scored, source="history")


# ---------------------------------------------------------------- main

def run_once(cfg, mode="auto", csv_path=None, pcap_path=None):
    ts_epoch = time.time()
    ts = datetime.now(timezone.utc)
    hist = load_history(days=int(cfg.get("baseline_days", 7)))
    scored, source, probe_status = [], "router", None

    if csv_path:
        clients = read_csv_clients(csv_path)
        source = f"csv:{csv_path}"
        for c in clients:
            scored.append(score_client(
                c, baseline=baseline_median(hist, c["mac"]),
                ttl_seen=c.get("ttl_seen"),
                os_fingerprints=c.get("os_fingerprints") or [],
                spike_multiplier=float(cfg.get("spike_multiplier", 3.0)),
                phone_threshold_mb=float(cfg.get("phone_down_threshold_mb_1h", 500))))
        append_history(clients, ts_epoch, source)

    elif mode == "gateway" or cfg.get("gateway_mode"):
        # Gateway mode: TTL evidence is the proof signal. Client list still
        # comes from the router probe or CSV if supplied; TTL map overlays it.
        ttl_map = {}
        if pcap_path:
            ttl_map = ttl_evidence_from_pcap_text(Path(pcap_path).read_text(errors="ignore"))
        else:
            ttl_map = sniff_ttl_via_scapy(seconds=60) or sniff_ttl_via_tcpdump(seconds=60)
        clients, probe_status = probe_router(cfg)
        source = "gateway"
        for c in clients:
            ttls = ttl_map.get(c.get("ip", ""), set())
            ttl_seen = 63 if 63 in ttls else (127 if 127 in ttls else None)
            scored.append(score_client(
                c, baseline=baseline_median(hist, c["mac"]), ttl_seen=ttl_seen,
                spike_multiplier=float(cfg.get("spike_multiplier", 3.0)),
                phone_threshold_mb=float(cfg.get("phone_down_threshold_mb_1h", 500))))
        append_history(clients, ts_epoch, source)

    else:  # Mode A default
        clients, probe_status = probe_router(cfg)
        for c in clients:
            scored.append(score_client(
                c, baseline=baseline_median(hist, c["mac"]),
                spike_multiplier=float(cfg.get("spike_multiplier", 3.0)),
                phone_threshold_mb=float(cfg.get("phone_down_threshold_mb_1h", 500))))
        if clients:
            append_history(clients, ts_epoch, source)

    path = generate_report(scored, ts=ts, source=source, probe_status=probe_status)
    flagged = [s for s in scored if s["level"] in ("SUSPECT", "PROOF")]
    print(f"Checked {len(scored)} clients, flagged {len(flagged)}.")
    print(f"Report: {path}")
    if probe_status and not scored:
        print("Router probe found no client list — see report for the "
              "exact endpoints tried and how to set a custom URL, or use --csv.")
    return path


def main(argv=None):
    load_dotenv()
    ap = argparse.ArgumentParser(description="hotspot-watch agent")
    ap.add_argument("--config", default=None)
    ap.add_argument("--once", action="store_true", help="run one cycle then exit")
    ap.add_argument("--report", action="store_true", help="regenerate report from history")
    ap.add_argument("--mode", choices=["auto", "router", "gateway", "csv"], default="auto")
    ap.add_argument("--csv", default=None, help="Mode C: CSV export path")
    ap.add_argument("--pcap", default=None, help="gateway mode: tcpdump -v text file")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)

    if args.report:
        p = regenerate_report_from_history()
        if p:
            print(f"Report regenerated: {p}")
        return 0

    if args.once or args.csv or args.pcap or args.mode != "auto":
        run_once(cfg, mode=args.mode, csv_path=args.csv, pcap_path=args.pcap)
        return 0

    # loop mode
    interval = int(cfg.get("poll_interval_minutes", 5)) * 60
    print(f"hotspot-watch looping every {interval // 60} min. Ctrl-C to stop.")
    while True:
        try:
            run_once(cfg, mode="router")
        except Exception as e:  # keep looping; log the failure
            print(f"[error] cycle failed: {e}", file=sys.stderr)
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
