"""Scan the independently planted prompts and score PromptRed against the key.

Runs the real default scan pipeline (taxonomy attacks + verbatim Gandalf
replays, LLM judge with calibrated abstention and panel escalation) on
each prompt in planted_prompts.json. Results are saved per (prompt,
category) unit, so a killed run resumes where it stopped and loses at
most one unit (a first run saving per prompt was killed mid-prompt and
lost $0.08 of results). The real OpenRouter balance is
checked before each prompt, and the run stops if total account usage
passes USAGE_STOP_AT.

Run: .venv/Scripts/python.exe data/holdout_planted/scan_planted_prompts.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from dotenv import load_dotenv  # noqa: E402

from core.llm.account_status import get_account_credit_status  # noqa: E402
from core.orchestrator import ScanOrchestrator  # noqa: E402

PLANTED_PATH = Path("data/holdout_planted/planted_prompts.json")
RESULTS_DIR = Path("data/holdout_planted/scan_results")
STRATEGIES = ["taxonomy", "gandalf"]
USAGE_STOP_AT = 3.70  # account usage in USD; baseline was 1.7876
CATEGORIES = [
    "system_prompt_extraction",
    "unauthorized_refund",
    "cross_user_data_access",
    "policy_circumvention",
]


def main() -> int:
    load_dotenv()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    prompts = json.loads(PLANTED_PATH.read_text(encoding="utf-8"))["prompts"]

    for prompt in prompts:
        for category in CATEGORIES:
            out = RESULTS_DIR / f"{prompt['id']}__{category}.json"
            if out.exists():
                continue

            status = get_account_credit_status()
            usage = status.usage if status else None
            print(f"{prompt['id']} {category}: usage before = {usage}", flush=True)
            if usage is None or usage >= USAGE_STOP_AT:
                print("Stopping: balance unknown or budget reached.", flush=True)
                return 1

            orchestrator = ScanOrchestrator(strategy_names=STRATEGIES)
            result = orchestrator.scan_many(
                [(prompt["id"], prompt["system_prompt"])],
                guardrails=[category],
                turns=1,
            )
            out.write_text(
                json.dumps(
                    {
                        "prompt_id": prompt["id"],
                        "guardrail_category": category,
                        "planted_vulnerabilities": prompt["planted_vulnerabilities"],
                        "usage_before": usage,
                        "findings": [f.to_dict() for f in result.findings],
                        "token_summary": result.token_summary,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            print(
                f"{prompt['id']} {category}: {len(result.findings)} attacks, "
                f"confirmed={len(result.vulnerable_findings)}, "
                f"needs_review={len(result.needs_review_findings)}",
                flush=True,
            )

    status = get_account_credit_status()
    print(f"Final account usage = {status.usage if status else None}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
