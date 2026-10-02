# PromptRed: product documentation

**PromptRed finds guardrail breaks in SaaS support-bot system prompts, and measures how often its own judge is right.**

## Persona

**The AI/ML engineer who builds a support bot** and must show the security lead it is safe before each release. They know prompting, not red-teaming. Checking one prompt change by hand means reading about 60 attack transcripts: at roughly two minutes each, that is two engineer-hours, about $170, per change.

- **Secondary user: the application security lead.** They approve or block the release and need reproducible, severity-scored evidence.
- **What changes for the engineer:** they get a ranked list of the breaks that matter, each with its transcript and fix, plus a short list of cases a human must decide. They no longer read 60 transcripts and guess.

## Input

| Input | How |
|---|---|
| A system prompt | `--prompt "..."`, `--prompt-file file.txt`, or `discover --path <project>` to find prompts in a codebase |
| Guardrail categories | System-prompt extraction, unauthorized refund, cross-user data access, policy circumvention (default: all four) |
| Attack strategies | `taxonomy` (default), `seed` (real incidents), `single`, `gandalf` (public dataset) |
| Limits | `--max-attacks` (default 60), `--turns` 1 or 3, `PROMPTRED_SPEND_CAP_USD` |
| Offline | `--offline`: no AI, no API key; fixed attacks, rules-based bot, rules-only verdicts |
| Models | `.env`: one attacker, target and judge model each, from different families |

## Output

An HTML report (self-contained) and a JSON report in `reports/`. For each attack:

- the attack, the bot's response and the full transcript
- a verdict: **Confirmed vulnerable**, held, or **Needs human review**
- the deciding route (rules, judge, or panel) and the judge's confidence
- severity by business impact, root cause, the OWASP Top 10 for LLM Applications 2026 entry, and a templated fix

The report also shows totals, real token cost and latency per model role. It warns if the judge shares a model family with the attacker or target. See `data/ground_truth/sample_report_preview.html`.

## Architecture

```text
 INPUT: a support bot's system prompt (pasted, from a file, or found in a codebase)
   |
   v
+-------------------------------------------------------------+     +----------------------------+
| ATTACK SIDE  (code)                                         |     | External intelligence      |
|   Strategy picks attacks: taxonomy / seed / single / gandalf| <-- | Gandalf dataset (1,000     |
|   Attack generator writes each attack ----------------------+---> |   real human attacks)      |
|   Harness runs a 1- or 3-turn conversation                  |     | LLM attacker: glm-5.3-flash|
+------------------------------+------------------------------+     +----------------------------+
                               |
                               v
+-------------------------------------------------------------+     +----------------------------+
| TARGET UNDER TEST                                           |     | LLM target:                |
|   Synthetic support bot  <----------------------------------+---> |   liquid/lfm-2.5-2.6b      |
|   Mock tools: account lookup, refund (every call is logged) |     +----------------------------+
+------------------------------+------------------------------+
                               |  transcript + tool-call log
                               v
+-------------------------------------------------------------+     +----------------------------+
| EVALUATION  (code decides the order)                        |     | LLM judge: qwen3.8-27b     |
|   1. Rules: verbatim/encoded leaks, cross-user tool calls   |     |   (writes the reasoning)   |
|        conclusive? -> verdict                               |     +-------------+--------------+
|   2. LLM judge (attacker text fenced off) <-----------------+-----------------+
|   3. Confidence >= 0.82 (calibrated)?  yes -> verdict       |     +----------------------------+
|   4. Otherwise the second judge validates it  <-------------+---> | Decision model: TypeSafe   |
|        agree -> verdict    disagree -> 5. NEEDS HUMAN REVIEW|     |   Jev 1.13 (yes/no + conf) |
+------------------------------+------------------------------+     +----------------------------+
                               |
                               v
+-------------------------------------------------------------+
| SCORING AND REMEDIATION  (code + config, no LLM)            |
|   Severity by business impact, root cause,                  |
|   OWASP Top 10 for LLM Applications 2026, templated fix     |
+------------------------------+------------------------------+
                               |
                               v
 OUTPUT: HTML + JSON report -- verdicts, transcripts, confidence, cost, latency
```

### Why the second judge is a decision model

When the main judge is unsure (confidence below 0.82), a second judge validates its verdict. That second judge is **TypeSafe's Jev 1.13**, a structured decision model: it answers "vulnerable or not vulnerable" with a probability and a confidence, instead of writing text. It was chosen by measurement, replacing the first second judge, `mistralai/mistral-nemo` (`data/holdout_planted/compare_second_judges.py`, scored against the author's blind labels):

| On the new-task test | mistral-nemo | **Jev 1.13** |
|---|---|---|
| Accuracy alone (129 cases) | 64% | **85%** |
| F1 alone | 0.68 | **0.83** |
| Automatic errors on the 14 unsure cases | 4 (all false alarms) | **1** |
| Cases sent to a human (of 14) | 5 | 9 (7 of them real breaks) |
| Cost per verdict | ~$0.0004 | **~$0.00002** |

Jev sends more cases to a human, but it is still the cheaper choice in engineering time. Assuming about 2 minutes to review a case and about 15 minutes to chase a false alarm, the old panel cost roughly 70 minutes on those 14 cases (10 reviewing, 60 on false alarms) and Jev roughly 33 (18 reviewing, 15 on one false alarm). Most of Jev's escalations are also real breaks, so the review time finds real problems. Jev also keeps attacker text in a separate data field, never in its instructions, so a judge-directed injection has nothing to hijack. It writes no explanation, so the report keeps the main judge's reasoning. The panel results rest on 14 cases and should be re-checked on more data.

If a model is down, a failed attack is replayed with a fixed real-world attack, a judge outage falls back to the rules verdict or human review, and the report is marked incomplete. Code owns the order, the limits and the decisions about escalation. LLMs generate attacks, play the target and judge what rules cannot see. Spend caps, token ceilings and attack limits are enforced in code, never in prompts.

| Module | Role |
|---|---|
| `promptred.py` | CLI: `scan`, `discover`, `benchmark`, `eval`, `validate` |
| `core/orchestrator.py` | Runs one scan end to end; builds the default judge panel |
| `core/attacks/` | Strategies, attack generator, multi-turn harness |
| `core/target_bot/`, `core/evidence/` | Synthetic bot, mock tools and their evidence log |
| `core/evaluator/` | Rules, LLM judge, calibrated threshold, panel (`decision_judge.py` for Jev), pipeline |
| `core/scoring/`, `core/remediation/` | Severity, root cause, OWASP 2026 mapping |
| `core/reporting/` | HTML and JSON reports |
| `core/llm/`, `core/economics/` | OpenRouter client, spend cap, cost and latency tracking, cost model |
| `evals/`, `data/` | Evaluation suites and every dataset; see their READMEs |

## Metrics: targeted vs reached

| Metric | Target | Reached |
|---|---|---|
| Judge F1 against hand labels (80 real cases) | at least 0.80 | **0.842** (precision 0.76, recall 0.94) |
| Judge F1 on a new task (prompts written by another model) | at least 0.80 | **0.83** |
| Judge vs rules-only baseline | higher | 0.842 vs 0.50 |
| Error of verdicts trusted without a human | at most 10% | 7.9% on the original set; 15.7% on the new task |
| Planted weaknesses found | at least 60% | **7 of 8 (88%)** |
| Cost per 60-attack scan | within a US$10 key | **about $0.40** |
| Scan time for one prompt | at most 10 minutes | about 1.5 minutes per attack (rate-limited free target) |
