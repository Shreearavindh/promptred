"""Live, minimal, cost-tracked test of the calibrated-selective-
evaluation + panel-escalation wiring built this session - not a full
re-run of the ground truth, a deliberate small sample chosen to
exercise BOTH code paths on purpose:

- 3 cases the primary judge was previously confident on (>= the
  calibrated threshold 0.82) - should be trusted directly, panel must
  NOT be called.
- 3 cases the primary judge was previously below threshold on
  (< 0.82) - should abstain and escalate to the panel.

Panel's second member uses the minimum-cost capable paid model found
live on OpenRouter (mistralai/mistral-nemo, $0.019/M prompt + $0.03/M
completion) - a distinct family from the primary judge (qwen), the
attacker (z-ai/glm), and the target (liquid), so the panel actually
adds independence rather than just cost.

Real cost is measured via the OpenRouter account balance before and
after (core/llm/account_status.py), not TokenTracker's self-reported
number - see the 2026-09-08 price-table bug in memory for why the
tracker's own number isn't trusted for this without a verified entry.
"""

import json
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from core.evaluator.deterministic import EvaluationContext
from core.evaluator.judge_panel import JudgePanel
from core.evaluator.llm_judge import LLMJudge
from core.evaluator.pipeline import EvaluationPipeline
from core.llm.account_status import get_account_credit_status
from core.llm.client import LLMClient

LABELS_PATH = Path("data/ground_truth/real_labelled_cases.jsonl")

ABOVE_THRESHOLD_CASES = ["RT-CDA-01", "RT-CDA-02", "RT-CDA-03"]
BELOW_THRESHOLD_CASES = ["RT-POL-18", "RT2-SPE-06", "RT2-REF-07"]
TEST_CASE_IDS = ABOVE_THRESHOLD_CASES + BELOW_THRESHOLD_CASES

PANEL_SECOND_MODEL = "mistralai/mistral-nemo"


def load_cases() -> dict[str, dict]:
    records = {
        json.loads(l)["case_id"]: json.loads(l)
        for l in LABELS_PATH.open(encoding="utf-8")
    }
    return {cid: records[cid] for cid in TEST_CASE_IDS}


def main() -> None:
    before = get_account_credit_status()
    print("=== BEFORE ===")
    print(json.dumps(before.to_dict() if before else None, indent=2))
    print()

    primary_judge = LLMJudge()  # loads real calibration -> threshold 0.82
    print(f"Primary judge calibrated threshold: {primary_judge.abstention_threshold}")

    panel = JudgePanel(
        judges=[
            LLMJudge(),  # fresh instance, same primary model (qwen)
            LLMJudge(llm_client=LLMClient(model=PANEL_SECOND_MODEL)),
        ],
        abstention_threshold=primary_judge.abstention_threshold,
    )

    pipeline = EvaluationPipeline(
        llm_judge=primary_judge,
        force_llm_judge=True,
        escalation_panel=panel,
    )

    cases = load_cases()
    correct = 0

    for case_id, r in cases.items():
        context = EvaluationContext(
            system_prompt=r["system_prompt"],
            guardrail_category=r["guardrail_category"],
            requesting_user_id=r["requesting_user_id"],
            customer_records=r["customer_records"],
        )
        transcript = [
            {"role": "user", "content": r["attack"]},
            {"role": "assistant", "content": r["response"]},
        ]

        result = pipeline.evaluate(
            attack=r["attack"],
            response=r["response"],
            transcript=transcript,
            evidence_events=r["evidence_events"],
            context=context,
        )

        expected = r["human_label"]["vulnerable"]
        match = result.vulnerable == expected
        correct += match
        expected_path = (
            "ESCALATE" if case_id in BELOW_THRESHOLD_CASES else "DIRECT"
        )
        actual_path = "ESCALATE" if result.escalated_to_panel else "DIRECT"
        path_ok = "OK" if expected_path == actual_path else "MISMATCH"

        print(
            f"{case_id}: predicted={result.vulnerable} expected={expected} "
            f"{'OK' if match else 'WRONG'} | confidence={result.confidence:.2f} "
            f"| path={actual_path} (expected {expected_path}, {path_ok})"
        )

    print()
    print(f"{correct}/{len(cases)} correct on this small sample.")

    after = get_account_credit_status()
    print()
    print("=== AFTER ===")
    print(json.dumps(after.to_dict() if after else None, indent=2))

    if before and after:
        delta = after.usage - before.usage
        print()
        print(f"REAL COST OF THIS TEST: ${delta:.6f}")


if __name__ == "__main__":
    main()
