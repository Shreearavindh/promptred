"""Confirm the "second judge checks every verdict" filter live, on the 129 new-task cases.

Re-judges the saved attack/response transcripts through the exact
evaluation pipeline a real scan now uses (rules -> main judge -> Jev
checks every judge verdict -> agree = verdict, disagree = human review)
and scores the result against the author's blind labels. Only the judges
run; the attacks and bot responses are the saved ones, so the comparison
with the earlier pipeline is like for like.

Caveat: the mock tool-call evidence log was not saved with the original
findings, so the rules layer sees the response text but not that log.

Each verdict is cached in rejudge_with_filter_cache.jsonl as it arrives.
Run: .venv/Scripts/python.exe data/holdout_planted/rejudge_with_filter.py
"""

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

import compare_second_judges as cases_source  # noqa: E402
import evaluate_judge_on_holdout as holdout  # noqa: E402
from core.evaluator.deterministic import EvaluationContext  # noqa: E402
from core.llm.token_tracker import TokenTracker  # noqa: E402
from core.orchestrator import CUSTOMER_RECORDS, ScanOrchestrator  # noqa: E402

HERE = Path(__file__).resolve().parent
CACHE = HERE / "rejudge_with_filter_cache.jsonl"


def route_of(ev) -> str:
    if ev.abstained:
        return "human review"
    if not ev.used_llm_judge:
        return "rules"
    if ev.judge_unavailable:
        return "unvalidated"
    return "judges agreed"


def main() -> None:
    labels = holdout.load_author_labels()
    cases = cases_source.load_cases()
    tracker = TokenTracker(spend_cap_usd=1.50)
    pipeline = ScanOrchestrator(token_tracker=tracker).pipeline
    assert pipeline.validate_every_verdict, "default pipeline must filter every verdict"

    done = {}
    if CACHE.exists():
        for line in CACHE.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                done[rec["key"]] = rec

    with CACHE.open("a", encoding="utf-8") as out:
        for case in cases:
            if case["key"] in done:
                continue
            transcript = case["transcript"]
            try:
                ev = pipeline.evaluate(
                    attack=transcript[-2]["content"],
                    response=transcript[-1]["content"],
                    transcript=transcript,
                    evidence_events=[],
                    context=EvaluationContext(
                        system_prompt=case["system_prompt"],
                        guardrail_category=case["category"],
                        requesting_user_id="A001",
                        customer_records=CUSTOMER_RECORDS,
                    ),
                )
                rec = {"key": case["key"], "route": route_of(ev),
                       "vulnerable": ev.vulnerable, "confidence": ev.confidence}
            except Exception as exc:  # noqa: BLE001 - spend cap included: recorded, then stop
                rec = {"key": case["key"], "error": f"{type(exc).__name__}: {exc}"}
                if "SpendCap" in type(exc).__name__:
                    print("Spend cap reached - stopping.", flush=True)
                    break
            out.write(json.dumps(rec) + "\n")
            out.flush()
            done[case["key"]] = rec
            print(f"{case['key']}: {rec.get('route', rec.get('error'))}", flush=True)

    recs = [done[c["key"]] for c in cases if c["key"] in done]
    routes = Counter(r.get("route", "error") for r in recs)
    auto = [r for r in recs if r.get("route") in ("rules", "judges agreed", "unvalidated")]
    truth = lambda key: labels[key] == "real"  # noqa: E731
    right = sum(r["vulnerable"] == truth(r["key"]) for r in auto)
    fa = sum(r["vulnerable"] and not truth(r["key"]) for r in auto)
    miss = sum(not r["vulnerable"] and truth(r["key"]) for r in auto)
    print(f"\n== LIVE filter on {len(recs)} of {len(cases)} new-task cases (author's blind labels) ==")
    print(f"Routes: {dict(routes)}")
    print(f"Automatic verdicts: {len(auto)}  right {right}  accuracy {right / len(auto):.3f}  "
          f"false alarms {fa}  missed breaks {miss}")
    print(f"Human reviews: {routes.get('human review', 0)} "
          f"({routes.get('human review', 0) / len(recs):.0%}), of which real breaks: "
          f"{sum(truth(r['key']) for r in recs if r.get('route') == 'human review')}")
    print("Before (old pipeline, as run): automatic 124, right 104 (0.839), false alarms 12, "
          "missed 8, human 5")
    print("Simulated (new filter):        automatic 113, right 102 (0.903), false alarms 3, "
          "missed 8, human 16")
    print(f"Tracker estimate for this run: ${tracker.total_cost():.4f}")


if __name__ == "__main__":
    main()
