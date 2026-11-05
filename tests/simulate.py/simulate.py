#!/usr/bin/env python3
"""hotspot-watch — tests/simulate.py
Feed fake client data and verify scoring flags the right clients.

Cases:
  1. NORMAL phone: 120 MB in 1h, baseline 110 MB — should be NORMAL.
  2. HOTSPOT SHARER: 650 MB in 1h, baseline 110 MB (5.9x) — SUSPECT.
     (spike alone triggers it; 650 MB also crosses the 500 MB phone
     volume threshold, so it is flagged even on a first run with no
     baseline history yet)
  3. TTL-63 case: 150 MB in 1h, baseline 120 MB (no spike), but TTL 63
     seen in gateway mode — PROOF.

Expected: exactly cases 2 and 3 flagged, case 1 NOT flagged.
Run:  python3 tests/simulate.py   (from the hotspot-watch folder)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import score_client  # noqa: E402


def main():
    cases = [
        {
            "label": "1-normal-phone",
            "client": {"mac": "AA:BB:CC:11:22:33", "ip": "192.168.111.10",
                       "hostname": "Kashif-Phone", "up_mb": 20, "down_mb": 120,
                       "device_type": "phone"},
            "baseline": 110.0, "ttl_seen": None, "os_fingerprints": [],
            "expected": "NORMAL",
        },
        {
            "label": "2-hotspot-sharer-4x-spike",
            "client": {"mac": "AA:BB:CC:44:55:66", "ip": "192.168.111.11",
                       "hostname": "Ali-Phone", "up_mb": 90, "down_mb": 650,
                       "device_type": "phone"},
            "baseline": 110.0, "ttl_seen": None, "os_fingerprints": [],
            "expected": "SUSPECT",
        },
        {
            "label": "3-ttl-63-proof",
            "client": {"mac": "AA:BB:CC:77:88:99", "ip": "192.168.111.12",
                       "hostname": "Ahmed-Phone", "up_mb": 30, "down_mb": 150,
                       "device_type": "phone"},
            "baseline": 120.0, "ttl_seen": 63, "os_fingerprints": [],
            "expected": "PROOF",
        },
    ]

    results = []
    ok = True
    for c in cases:
        scored = score_client(
            c["client"], baseline=c["baseline"], ttl_seen=c["ttl_seen"],
            os_fingerprints=c["os_fingerprints"])
        passed = scored["level"] == c["expected"]
        ok = ok and passed
        results.append({
            "case": c["label"], "mac": scored["mac"],
            "down_mb": scored["down_mb"], "baseline_mb": c["baseline"],
            "ttl_seen": c["ttl_seen"], "expected": c["expected"],
            "got": scored["level"], "score": scored["score"],
            "reasons": scored["reasons"], "PASS": passed,
        })
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {c['label']}: expected={c['expected']} "
              f"got={scored['level']} score={scored['score']}")
        for r in scored["reasons"]:
            print(f"        reason: {r}")

    # Also verify the full pipeline: CSV mode end-to-end (no router needed).
    print("\n[csv] end-to-end check via sample CSV ...")
    from agent import read_csv_clients, generate_report, load_history  # noqa
    csv_path = Path(__file__).resolve().parent / "sample-clients.csv"
    clients = read_csv_clients(csv_path)
    assert len(clients) == 3, f"sample CSV should have 3 rows, got {len(clients)}"
    scored_csv = [
        score_client(cl, baseline=110.0 if cl["mac"].endswith("33") or cl["mac"].endswith("66") else 120.0,
                     ttl_seen=cl.get("ttl_seen"),
                     os_fingerprints=cl.get("os_fingerprints") or [])
        for cl in clients
    ]
    flagged = [s for s in scored_csv if s["level"] in ("SUSPECT", "PROOF")]
    print(f"[csv] flagged {len(flagged)}/3 (expected 2): "
          f"{[s['mac'] for s in flagged]}")
    ok = ok and len(flagged) == 2

    print("\nOVERALL:", "ALL TESTS PASSED" if ok else "TESTS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
