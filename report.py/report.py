#!/usr/bin/env python3
"""hotspot-watch — report.py
Regenerate the markdown report from data/history.jsonl.
Same as: python3 agent.py --report
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent import load_dotenv, regenerate_report_from_history  # noqa: E402

if __name__ == "__main__":
    load_dotenv()
    path = regenerate_report_from_history()
    if path:
        print(f"Report regenerated: {path}")
