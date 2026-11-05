# hotspot-watch — Test Result

**Date:** 2026-11-05 (PKT) · **Python:** 3.12.3 · **Run from:** `~/workspace/hotspot-watch/`

## 1. Unit / scoring test — `python3 tests/simulate.py`

```
[PASS] 1-normal-phone: expected=NORMAL got=NORMAL score=0
[PASS] 2-hotspot-sharer-4x-spike: expected=SUSPECT got=SUSPECT score=100
        reason: Traffic spike: 650 MB in 1h vs 7-day median 110 MB (5.9x baseline)
        reason: Phone-only MAC used 650 MB down in 1h (threshold 500 MB)
[PASS] 3-ttl-63-proof: expected=PROOF got=PROOF score=100
        reason: TTL 63 seen in gateway mode — packet passed through one extra hop (phone hotspot NAT). Android/iOS TTL 64 -> 63, Windows 128 -> 127.

[csv] end-to-end check via sample CSV ...
[csv] flagged 2/3 (expected 2): ['AA:BB:CC:44:55:66', 'AA:BB:CC:77:88:99']

OVERALL: ALL TESTS PASSED
```

**Verdict:** the normal phone was NOT flagged; the 4x/5.9x traffic sharer was
flagged SUSPECT; the TTL-63 case was flagged PROOF. Exactly the right two.

## 2. CSV end-to-end (fresh install, no baseline history yet)

Command: `python3 agent.py --once --csv tests/sample-clients.csv`

```
Checked 3 clients, flagged 2.
Report: reports/report-2026-11-05-1548.md
AA:BB:CC:11:22:33 NORMAL 0
AA:BB:CC:44:55:66 SUSPECT 50
AA:BB:CC:77:88:99 PROOF 100
```

A second identical run also flagged 2/3. `python3 report.py` regenerated the
same report from `data/history.jsonl` without error.

## 3. Spike-only check (baseline present, volume below 500 MB)

Seeded 7 days of 110 MB baseline for `AA:BB:CC:44:55:66`, then fed a
480 MB / 1h row (4.4x baseline, under the 500 MB volume threshold):

```
Checked 1 clients, flagged 1.
[('AA:BB:CC:44:55:66', 'SUSPECT', 50, 110.0)]
```

Proves the >3x spike rule flags on its own, independent of the volume rule.

## 4. TTL parsing check (gateway mode, no scapy needed)

Fed tcpdump-style text with TTL 63, 64 and 127:

```
{'192.168.111.11': {63}, '192.168.111.10': {64}, '192.168.111.12': {127}}
TTL parse OK: 63 and 127 detected, 64 not flagged
```

## 5. Router probe — graceful failure (no router on this machine)

Command: `timeout 60 python3 agent.py --once` (no 192.168.111.1 reachable here)

```
Checked 0 clients, flagged 0.
Report: reports/report-2026-11-05-1548.md
Router probe found no client list — see report for the exact endpoints tried
and how to set a custom URL, or use --csv.
probe exit: 0
```

- 6 candidate eWeb endpoints tried, all logged in the report + debug file
  `data/debug/router-probe-20261105-154836.json`.
- **No fake client data was invented.** `latest.json` honestly reports
  `clients_checked: 0`.
- This is the expected behaviour on any machine that is not on the user's
  LAN. On the user's Pi/PC the same code will try the same endpoints
  against the real 192.168.111.1.

## 6. Bugs found and fixed during testing

1. **Scoring weights:** the 500 MB volume rule added only 40 points, below
   the 50-point SUSPECT threshold, so it could never flag on its own.
   Fixed: volume rule and mixed-OS rule now add 50 each, so every
   OR-condition in the spec flags independently. Re-tested — all green.
2. **Sample data:** the sharer in `tests/sample-clients.csv` was 480 MB,
   which needs baseline history to flag. Raised to 650 MB so the volume
   rule also catches it on a first run with no history.

## 7. Not tested (needs the user's LAN / hardware)

- Mode A against the real EW300N eWeb (endpoints are undocumented and
  vary by firmware — the probe logs what it finds; the user may need to
  set `router.client_list_url` in `config.yaml` from browser DevTools).
- Mode B live TTL sniffing on a real gateway (scapy/tcpdump parsing is
  unit-tested above, live capture is not).
- No GitHub account was created and nothing was pushed (per task — the
  repo files are local only, ready for the user to upload himself).
