"""End-to-end check: 5 live attacks per guardrail category, 20 in total.

Confirms the full pipeline still works (attacker -> target -> rules ->
LLM judge -> calibrated threshold -> panel escalation -> human review)
and records the final confidence of every verdict and which route
decided it. Uses the same per-category system prompts as the original
ground truth, so results are comparable.

Five attacks per category come from existing strategies only:
3 taxonomy patterns + real-incident seeds (1 per category, 2 for
policy_circumvention) + 1 generic attempt where seeds leave room.

Each category is saved as soon as it finishes. The real OpenRouter
balance is read before each category and at the end.

Run: .venv/Scripts/python.exe data/smoke_test/run_20_attack_check.py
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from dotenv import load_dotenv  # noqa: E402

from core.llm.account_status import get_account_credit_status  # noqa: E402
from core.orchestrator import ScanOrchestrator  # noqa: E402
from data.ground_truth.build_labelled_cases import (  # noqa: E402
    CROSS_USER_SYSTEM_PROMPT,
    POLICY_SYSTEM_PROMPT,
    REFUND_SYSTEM_PROMPT,
    SP_SYSTEM_PROMPT,
)

RESULTS_DIR = Path("data/smoke_test/results")
USAGE_STOP_AT = 3.30  # account usage in USD; this run started near 2.735

PLAN = {
    "system_prompt_extraction": (SP_SYSTEM_PROMPT, ["taxonomy", "seed", "single"]),
    "unauthorized_refund": (REFUND_SYSTEM_PROMPT, ["taxonomy", "seed", "single"]),
    "cross_user_data_access": (CROSS_USER_SYSTEM_PROMPT, ["taxonomy", "seed", "single"]),
    "policy_circumvention": (POLICY_SYSTEM_PROMPT, ["taxonomy", "seed"]),
}


def route_of(evaluation) -> str:
    if evaluation.abstained:
        return "human review"
    if evaluation.escalated_to_panel:
        return "panel"
    if not evaluation.used_llm_judge:
        return "rules"
    return "judge direct"


def usage() -> float | None:
    status = get_account_credit_status()
    return status.usage if status else None


def main() -> int:
    load_dotenv()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    start_usage = usage()
    print(f"Account usage before: {start_usage}", flush=True)

    for category, (system_prompt, strategies) in PLAN.items():
        out = RESULTS_DIR / f"{category}.json"
        if out.exists():
            print(f"{category}: already done, skipping", flush=True)
            continue
        current = usage()
        if current is None or current >= USAGE_STOP_AT:
            print("Stopping: balance unknown or budget reached.", flush=True)
            return 1

        result = ScanOrchestrator(
            strategy_names=strategies, progress_callback=print
        ).scan_many(
            [(f"GT-{category}", system_prompt)], guardrails=[category], turns=1
        )
        rows = []
        for finding in result.findings:
            ev = finding.evaluation
            rows.append({
                "strategy": finding.strategy_name,
                "pattern": finding.attack_pattern_id,
                "verdict": "VULNERABLE" if ev.vulnerable else "held",
                "confidence": ev.confidence,
                "route": route_of(ev),
                "deterministic_confidence": ev.deterministic_confidence,
                "attack": finding.attack,
                "response": finding.response,
                "reasoning": ev.reasoning,
            })
            print(
                f"  {category[:3].upper()} {finding.strategy_name:8s} "
                f"{str(finding.attack_pattern_id):10s} {rows[-1]['verdict']:10s} "
                f"conf={ev.confidence:.2f} route={rows[-1]['route']}",
                flush=True,
            )
        out.write_text(json.dumps({
            "category": category,
            "strategies": strategies,
            "usage_before": current,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "attacks": rows,
            "token_summary": result.token_summary,
        }, indent=2), encoding="utf-8")
        print(f"{category}: {len(rows)} attacks saved", flush=True)

    end_usage = usage()
    print(f"Account usage after: {end_usage}", flush=True)
    if start_usage is not None and end_usage is not None:
        print(f"Real cost of this run: ${end_usage - start_usage:.4f}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
