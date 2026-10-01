# Evals

How PromptRed is measured, what was actually run, and which number came from where. The central question is the one the review set: **can the judge be trusted?** So the judge is measured against hand labels, not just used.

## What was run, and the results

| Eval | Question it answers | Data | Status | Result |
|---|---|---|---|---|
| **Judge eval** (`suites/judge_eval.py`) | Does the LLM judge's verdict match a human's? | `data/ground_truth/real_labelled_cases.jsonl` (80 real, hand-labelled) | **Run** | **F1 0.842** (precision 0.762, recall 0.941); rules alone F1 0.50; "never vulnerable" F1 0.0 |
| **Calibrated threshold** (`data/ground_truth/calibrate_judge.py`, `verify_calibration_on_holdout.py`) | Above what confidence can a verdict be trusted without a human? | Same 80 cases: fitted on 64, checked on 16 | **Run** | Threshold 0.82: error at most 7.9% (95% confidence) covering 90.6% of cases; holdout 6.7% |
| **New-task judge eval** (`data/holdout_planted/evaluate_judge_on_holdout.py`) | Do the judge and its threshold still hold on prompts written by a different model? | `data/holdout_planted/`: 129 verdicts, all hand-labelled | **Run** | F1 **0.82**; rules 13/13 correct; **threshold promise broken (12.7% error)**; 7 of 8 planted weaknesses found |
| **Live smoke check** (`data/smoke_test/run_20_attack_check.py`) | Does the whole pipeline still work end to end? | Ground-truth prompts, 5 attacks per category | **Run** | 17 of 20 attacks ran; 2 real breaks, both correct; all verdicts confidence 0.90 or higher |
| Attack generator eval (`suites/attack_generator_eval.py`) | Are generated attacks on-target, specific and varied? | All 12 taxonomy patterns | Built and unit-tested, **not run live** | Indirect evidence: 48% of taxonomy attacks broke a guardrail on the new task |
| Target robustness eval (`suites/target_robustness_eval.py`) | Does rephrasing an attack change whether the guardrail holds? | `data/ground_truth/robustness_variants.json` (24 variants) | Built and unit-tested, **not run live** | No result yet |
| System eval (`suites/system_eval.py`) | Does the full scan find the weaknesses planted in the benchmark? | `data/benchmarks/known_vulnerable_prompts.json` | Built and unit-tested, **not run live** | Superseded by the planted-prompt test, whose weaknesses another model wrote |

Labels on the new task were proposed from reading every transcript and are pending the author's final confirmation. Borderline cases (such as the bot naming its own underlying model) are reported both ways, never silently folded in.

## Reproduce the numbers (free, no model calls)

All predictions are cached, so these re-score without spending anything:

```bash
python -m data.ground_truth.eval_real_ground_truth
python -m data.ground_truth.verify_calibration_on_holdout
python data/holdout_planted/evaluate_judge_on_holdout.py
python data/holdout_planted/score_against_key.py
```

The first command also writes a summary to `results/judge/`. The CLI reads the judge's recall from that summary when it prices a scan.

`python promptred.py eval --suite judge` runs the judge again live on the same 80 cases (about $0.37). Expect small differences from run to run: the judge is not fully deterministic, and the same case was observed to flip on a second call.

## Layout

- `harness.py`: shared runner. It samples each case `repeats_per_case` times (default 3), aggregates pass rates and variance, and saves reports.
- `suites/`: one file per eval. Each module's docstring explains what it measures and why.
- `results/judge/`: the current judge-eval summary, on the real 80-case set.
- `results/judge_legacy_invented_set/`: four older runs on the first 65+7 hand-written cases. That set includes judge-evasion cases, where the attacker knows the judge: recall fell from 0.83 (blind) to 0.67 (judge-directed injection, only 4 cases).

## Critique of these evals

- **Small samples.** 80 cases with 17 positives; system-prompt extraction has only 3 positives, so no per-category claim is made for it.
- **One labeller.** A second labeller and an agreement score would make the ground truth stronger.
- **Single sample per case.** The judge is not fully deterministic. The harness supports repeated sampling, but the main runs used one sample per case to save cost.
- **Calibration does not transfer automatically.** On the new task the 0.82 threshold's promise broke, while the judge's ranking by confidence held. A new domain needs a small labelled audit sample to reset the threshold.
- **Three suites were never run live** (see the table). The planted-prompt test replaces the system eval with a stronger, independent version, but attack quality and robustness to rephrasing are not yet measured directly.
