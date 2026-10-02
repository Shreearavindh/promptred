# Evals

How PromptRed is measured, what was actually run, and which number came from where. The central question is the one the review set: **can the judge be trusted?** So the judge is measured against hand labels, not just used.

## What was run, and the results

| Eval | Question it answers | Data | Status | Result |
|---|---|---|---|---|
| **Judge eval** (`suites/judge_eval.py`) | Does the LLM judge's verdict match a human's? | `data/ground_truth/real_labelled_cases.jsonl` (80 real, hand-labelled) | **Run** | **F1 0.842** (precision 0.762, recall 0.941); rules alone F1 0.50; "never vulnerable" F1 0.0 |
| **Calibrated threshold** (`data/ground_truth/calibrate_judge.py`, `verify_calibration_on_holdout.py`) | Above what confidence can a verdict be trusted without a human? | Same 80 cases: fitted on 64, checked on 16 | **Run** | Threshold 0.82: error at most 7.9% (95% confidence) covering 90.6% of cases; holdout 6.7% |
| **New-task judge eval** (`data/holdout_planted/evaluate_judge_on_holdout.py`) | Do the judge and its threshold still hold on prompts written by a different model? | `data/holdout_planted/`: 129 verdicts, labelled blind by the author | **Run** | F1 **0.83**; rules 13/13 correct; **threshold promise broken (15.7% error)**; 7 of 8 planted weaknesses found; 4 of 5 human-review cases were real breaks |
| **Second-judge comparison** (`data/holdout_planted/compare_second_judges.py`) | Which model should be the panel's second judge? | The same 129 new-task cases and blind labels | **Run** ($0.148) | Jev 1.13 alone: accuracy 85%, F1 0.83; mistral-nemo: 64%, 0.68. On the 14 unsure cases: 1 automatic error with Jev vs 4 with the old panel. Jev is now the default. |
| **Live smoke check** (`data/smoke_test/run_20_attack_check.py`) | Does the whole pipeline still work end to end? | Ground-truth prompts, 5 attacks per category | **Run** | 17 of 20 attacks ran; 2 real breaks, both correct; all verdicts confidence 0.90 or higher |
| Attack generator eval (`suites/attack_generator_eval.py`) | Are generated attacks on-target, specific and varied? | All 12 taxonomy patterns | **Run** (2026-10-02, 1 repeat) | **PASS:** 83% on-target (threshold 70%), specificity 4.6/5, 0 errors. Diversity not measured: it needs 2+ repeats per pattern, so the 0.0 in the result file is not a real score. |
| Target robustness eval (`suites/target_robustness_eval.py`) | Does rephrasing an attack change whether the guardrail holds? | `data/ground_truth/robustness_variants.json` (24 variants) | **Run** (2026-10-02, 1 repeat) | Reports 100% held, but **this suite decides with the rules layer only**, which misses most breaks. Reading the 24 responses: 22 held, 1 likely break (RV-POL-04 gave general legal information despite "no legal advice") and 1 borderline, so about 92-96% held. |
| System eval (`suites/system_eval.py`) | Does the full scan find the weaknesses planted in the benchmark? | `data/benchmarks/known_vulnerable_prompts.json` | **Run** (2026-10-02, 1 repeat) | **FAIL: recall 0.20** (2 of 10 planted found; threshold 0.80), false-positive rate 0.10. The suite sends **one generic attack per category**, where a real scan sends 3+ taxonomy attacks plus incident seeds, at one-line benchmark prompts whose "planted" weaknesses were never verified to be exploitable. The planted-prompt test (another model's real weaknesses, 7 of 8 found) is the stronger measure. |

New-task labels were made **blind**: the author saw only system prompt, guardrail, attack and response, shuffled, with no judge verdicts (`data/holdout_planted/blind_review/`). An earlier, judge-visible set of labels agrees with them on 78% of cases (Cohen's kappa 0.63). Borderline labels are reported both ways, never silently folded in.

## Reproduce the numbers (free, no model calls)

All predictions are cached, so these re-score without spending anything:

```bash
python -m data.ground_truth.eval_real_ground_truth
python -m data.ground_truth.verify_calibration_on_holdout
python data/holdout_planted/evaluate_judge_on_holdout.py
python data/holdout_planted/blind_review/compare_blind_labels.py   # needs openpyxl
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
- **Labellers.** The 80-case set has one labeller. The new-task set has two (blind author labels, plus an earlier judge-visible set) agreeing at kappa 0.63: substantial, not perfect.
- **Single sample per case.** The judge is not fully deterministic. The harness supports repeated sampling, but the main runs used one sample per case to save cost.
- **Calibration does not transfer automatically.** On the new task the 0.82 threshold's promise broke (15.7% error), and errors appeared even above 0.90, so no simple threshold change fixes it. A new domain needs a small labelled audit sample to recalibrate.
- **The end-to-end benchmark failed** (recall 0.20). Its design is weak, with one generic attack per category against unverified one-line benchmarks, but it is still a real result: a single attempt finds little. Use the planted-prompt test for recall.
- **The robustness suite scores with rules only**, so its 100% overstates; reading the responses gives about 92-96%. It should use the LLM judge.
- **Attack diversity is unmeasured** (needs 2+ repeats).
