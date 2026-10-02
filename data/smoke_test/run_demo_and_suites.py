"""Run the video demo scan and the three never-run eval suites, under one budget.

Steps, in order, each as its own CLI process:
1. Demo scan of docs/demo/demo_prompt.txt (cross-user + policy, 9 attacks),
   which is also the first real scan with Jev as the default second judge.
2. eval --suite attack_generator   (1 repeat)
3. eval --suite target_robustness  (1 repeat)
4. eval --suite system             (1 repeat)

Budget: every step runs with PROMPTRED_SPEND_CAP_USD, and the real
OpenRouter balance is read before each step; the run stops if total
spend since the start reaches BUDGET_USD. Output goes to
run_demo_and_suites_log.txt; eval results land in evals/results/<suite>/.

Run: .venv/Scripts/python.exe data/smoke_test/run_demo_and_suites.py
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

BUDGET_USD = 2.50
PYTHON = str(ROOT / ".venv" / "Scripts" / "python.exe")
STEPS = [
    ("demo scan", ["promptred.py", "scan", "--prompt-file", "docs/demo/demo_prompt.txt",
                   "--guardrails", "cross_user_data_access,policy_circumvention",
                   "--strategies", "taxonomy,seed", "--max-attacks", "9",
                   "--output", "reports/"]),
    ("attack_generator eval", ["promptred.py", "eval", "--suite", "attack_generator", "--repeats", "1"]),
    ("target_robustness eval", ["promptred.py", "eval", "--suite", "target_robustness", "--repeats", "1"]),
    ("system eval", ["promptred.py", "eval", "--suite", "system", "--repeats", "1"]),
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
            print(f"STOP: budget reached (${spent:.4f} spent) before '{name}'", flush=True)
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
