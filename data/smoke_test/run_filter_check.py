"""Live confirmation of the "second judge checks every verdict" filter.

1. Fresh demo scan (docs/demo/demo_prompt.txt, 9 attacks): the filter end
   to end in a real scan.
2. Re-judge the 129 saved new-task cases through the new pipeline and
   score against the blind labels (data/holdout_planted/rejudge_with_filter.py).

Budget: real OpenRouter balance read before each step; stops if total
spend reaches BUDGET_USD. Log: run_filter_check_log.txt.
Run: .venv/Scripts/python.exe data/smoke_test/run_filter_check.py
"""

import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")
from core.llm.account_status import get_account_credit_status  # noqa: E402

BUDGET_USD = 1.50
PYTHON = str(ROOT / ".venv" / "Scripts" / "python.exe")
STEPS = [
    ("fresh demo scan", ["promptred.py", "scan", "--prompt-file", "docs/demo/demo_prompt.txt",
                         "--guardrails", "cross_user_data_access,policy_circumvention",
                         "--strategies", "taxonomy,seed", "--max-attacks", "9",
                         "--output", "reports/"]),
    ("re-judge 129 new-task cases", ["data/holdout_planted/rejudge_with_filter.py"]),
]


def usage() -> float:
    status = get_account_credit_status()
    if status is None:
        raise SystemExit("Could not read the account balance - stopping before spending.")
    return status.usage


def main() -> int:
    start = usage()
    print(f"[{datetime.now():%H:%M}] start, account usage {start:.4f}, budget ${BUDGET_USD}", flush=True)
    env = {**os.environ, "PROMPTRED_SPEND_CAP_USD": str(BUDGET_USD),
           "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
    for name, args in STEPS:
        spent = usage() - start
        if spent >= BUDGET_USD:
            print(f"STOP: budget reached (${spent:.4f}) before '{name}'", flush=True)
            return 1
        print(f"\n[{datetime.now():%H:%M}] === {name} (spent so far ${spent:.4f}) ===", flush=True)
        began = time.monotonic()
        result = subprocess.run([PYTHON, *args], cwd=ROOT, env=env)
        print(f"[{datetime.now():%H:%M}] === {name} finished: exit {result.returncode}, "
              f"{(time.monotonic() - began) / 60:.1f} min ===", flush=True)
    end = usage()
    print(f"\n[{datetime.now():%H:%M}] ALL DONE. Real cost ${end - start:.4f} "
          f"(usage {start:.4f} -> {end:.4f})", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
