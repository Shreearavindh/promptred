# Data

Every dataset PromptRed used, where it came from, and which number it produced. Nothing here was edited after a model saw it, unless a file says so.

## How the pieces fit

```
public_datasets/ + seeds/ + config/taxonomy.yaml   where attacks come from
            │
            ▼
ground_truth/      80 real attack/response pairs, hand-labelled  ->  judge F1 0.842
holdout_planted/   8 prompts written by another model, 129 verdicts hand-labelled
                                                                   ->  new-task test
smoke_test/        20-attack live check, 5 per category            ->  "does it still work"
benchmarks/        5 synthetic prompts for the `benchmark` command
```

## `public_datasets/` - attacks PromptRed did not write

| File | What it is |
|---|---|
| `gandalf_ignore_instructions.jsonl` | 1,000 real prompts people typed into Lakera's Gandalf game (July 2023), filtered by Lakera as "ignore your instructions" injections. MIT licence. |
| `gandalf_ignore_instructions.SOURCE.json` | Provenance: source URL, pinned revision, licence, paper, fetch date. |

Used by `--strategies gandalf`, which replays them verbatim with no attacker model. It applies to system-prompt extraction only; rows aimed at Gandalf's own password game are filtered out (`core/attacks/strategies/public_dataset.py`).

## `seeds/public_injection_seeds.json` - real incidents

Five documented, cited prompt-injection incidents: Bing/Sydney, the Chevrolet $1 Tahoe bot, DPD, DAN and the Microsoft 365 Copilot exfiltration. The `seed` strategy adapts them to each target. This is a curated incident list, not a benchmark dataset.

## `ground_truth/` - the main judge evaluation

The judge's headline numbers come from here. **Real transcripts, labelled by a human before the judge ran.**

| File | Role |
|---|---|
| `generate_real_cases.py` | Runs the real attacker against the real target (no judge) and saves raw transcripts. |
| `real_cases_raw.jsonl` | 80 raw transcripts, 20 per category. |
| `retest_spe_ref.py`, `real_cases_spe_ref_retest.jsonl` | Re-run of two categories after fixing a weak-attack bug (0/20 successes became 1/20 and 6/20). |
| `real_cases_proposed.jsonl`, `real_cases_spe_ref_retest_proposed.jsonl` | Proposed labels with reasons. |
| `REVIEW_real_cases.md`, `REVIEW_spe_ref_retest.md` | The human review sheets the labels were confirmed from. |
| `build_real_labelled_cases.py` -> **`real_labelled_cases.jsonl`** | **The ground truth: 80 cases, 17 vulnerable, split 64 calibration / 16 holdout** (the split is a fixed list of case IDs). |
| `eval_real_ground_truth.py` -> `real_judge_eval_results.jsonl` | The judge's prediction for every case (cached, so re-scoring is free). |
| `calibrate_judge.py` -> `config/judge_calibration.json` | Fits the confidence threshold (0.82) on the calibration split only. |
| `verify_calibration_on_holdout.py` | Checks that threshold on the untouched holdout split. |
| `live_test_calibration_and_panel.py` | 6-case live wiring test of the threshold and judge panel. A routing test, not an accuracy measure. |
| `real_cases_raw_validation_60.jsonl` | 60-case cost-validation run after the scan size was reduced to 60. |
| `sample_report_preview.html` | Example HTML report, including the human-review section. |
| `labelled_cases.jsonl`, `build_labelled_cases.py` | **Legacy.** The first 65+7 cases, whose text was written by hand rather than produced by models. Kept because it holds the only judge-evasion cases (attacker knows the judge); not used for headline numbers. |
| `robustness_variants.json` | 24 phrasing variants (paraphrase, obfuscation, framing) for the target-robustness eval. |

## `holdout_planted/` - judging the judge on a new task

Answers "you designed the weaknesses and the attacker, so you are testing against your own answer key".

| File | Role |
|---|---|
| `plant_vulnerable_prompts.py` -> **`planted_prompts.json`** | `deepseek/deepseek-v3.2` (a family used nowhere else in PromptRed) wrote 8 support-bot prompts and its own answer key: 6 prompts with 8 planted weaknesses, plus 2 strict controls. Saved unedited. |
| `planted_prompts_attempt1_gpt-4o-mini_REJECTED.json` | First attempt, rejected before any scan: greetings rather than instructions, and the "controls" were no stricter than the vulnerable prompts. Kept for transparency. |
| `scan_planted_prompts.py` -> `scan_results/` | Full scan of all 8 prompts x 4 categories: 129 verdicts, saved per prompt x category so a killed run can resume. |
| `blind_review/` -> **`hand_labels_blind_author.json`** | **The ground truth for this test:** the author's labels for all 129 verdicts, made blind (shuffled sheet with no judge verdicts; `DO_NOT_OPEN_blind_key.json` maps rows back). `compare_blind_labels.py` scores the judge and the earlier labels against them. |
| `hand_labels_confirmed_flags.json`, `hand_labels_held_verdicts.json` | Earlier labels, made while the judge's verdicts were visible; kept as a second labeller (78% agreement, kappa 0.63). |
| `compare_second_judges.py` -> `compare_second_judges_cache.jsonl` | Jev 1.13 vs mistral-nemo as the panel's second judge, against the blind labels (every answer cached; logs in `compare_second_judges_log.txt`). |
| `rejudge_with_filter.py` -> `rejudge_with_filter_cache.jsonl` | The 129 saved transcripts re-judged live through the every-verdict filter, scored against the blind labels (resumable cache; logs in `rejudge_resume_log.txt`). |
| `score_against_key.py` | Scores the scan against the planter's answer key. |
| `evaluate_judge_on_holdout.py` | Judge precision/recall/F1 on the new task, per-route accuracy, and whether the calibrated threshold's promise held. |
| `scan_log.txt`, `scan_err.txt` | Raw run logs. |

## `smoke_test/` - the latest live check

`run_20_attack_check.py` runs 5 live attacks per category against the same prompts as the ground truth. `results/` holds every attack, response, verdict, confidence and deciding route. Real cost: $0.0983.

## `benchmarks/known_vulnerable_prompts.json`

Five synthetic prompts with two planted weaknesses each, written for this project. They feed the `benchmark` command and the `system` eval suite. Because they were written alongside the attacker, `holdout_planted/` is the independent test.
