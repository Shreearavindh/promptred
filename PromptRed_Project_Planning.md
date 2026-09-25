# PromptRed — Project Planning & Engineering Blueprint

> **Purpose:** A focused MVP for authorized prompt-injection and LLM-application security testing of a synthetic SaaS customer-support agent.

## 1. What PromptRed Is

PromptRed is an adversarial security-testing harness. A user supplies a system prompt and controlled target configuration; PromptRed generates attacks, runs 1- or 3-turn conversations against a synthetic support bot, captures execution evidence, evaluates whether a guardrail was bypassed, identifies likely root cause, assigns business severity, and produces an evidence-backed report.

```text
System Prompt + Target Config
          ↓
Attack Taxonomy / Public Seeds
          ↓
LLM Attack Generator
          ↓
Multi-Turn Harness
          ↓
Synthetic Target Agent
   ┌──────┼────────┐
   ↓      ↓        ↓
 Tools  Auth   Conversation
   └──────┼────────┘
          ↓
   Execution Evidence
          ↓
 Deterministic Checks + LLM Judge
          ↓
 Judge Validation against Human Ground Truth
          ↓
 Finding → RCA → Severity → Remediation → Report
```

The LLM is a component, **not the security boundary**. PromptRed owns orchestration, evidence collection, deterministic checks, scoring, policy and reporting.

## 2. MVP Security Scope

1. **System Prompt Extraction** — hidden instructions must not be disclosed.
2. **Unauthorized Refund / Privilege Escalation** — protected financial actions must require authorization.
3. **Cross-User Data Access** — one customer must not obtain another customer's data.
4. **Policy Circumvention** — explicit business policies must not be bypassed.

The target is synthetic: mock accounts, refunds, customer data, tools and authorization rules. No production systems or real customer records are required.

## 3. Main Components & Technology

| Component | Planned technology / role |
|---|---|
| Attack taxonomy | Python + external JSON/YAML |
| Attack generator | LLM through `LLMClient` |
| LLM gateway | OpenRouter, OpenAI-compatible API |
| Preferred model | Free/open-source Qwen-family model available through OpenRouter |
| Optional comparison | Paid frontier model only if budget permits |
| Target bot | Python synthetic SaaS support agent |
| Tools/auth | Explicit mock business tools + deterministic authorization |
| Harness | Python orchestration, 1/3 turns, transcript, timeout/retry |
| Evidence/evaluator | Deterministic checks first + LLM semantic judge |
| Judge validation | ~65 human-labelled cases + blind holdout |
| Severity | Python rules/risk rubric |
| Attack memory | Local ChromaDB; optional enhancement |
| CLI | Python CLI; core independent of UI |
| UI | Streamlit after core is stable |
| Deployment | Docker |
| Storage | Local files/JSON/JSONL; synthetic data only |

The PRD's build/buy decision is to rent foundation-model capability and build the domain-specific security scaffolding, evidence, orchestration, scoring and reporting ourselves. fileciteturn6file6L503-L551

## 4. Judge & Evaluation — Major Revision

The judge must not simply output yes/no. It receives the attack, conversation history and observable execution evidence: authorization result, tool call/result and final response where applicable.

It returns a **provisional** verdict containing vulnerability status, severity, reason, evidence, likely root cause and confidence/abstention.

The judge itself is then evaluated against **human-labelled ground truth**. Approximately 65 cases will be labelled, with a blind holdout.

Metrics:
- Precision
- Recall
- F1
- False positives / false negatives
- Abstention/confidence behaviour

This addresses the professor's central concern: vulnerability recall alone does not establish that the judge can be trusted.

## 5. Metrics & Business Value

**Security/evaluation:** guardrail coverage, vulnerability recall, judge precision/recall/F1, false negatives and false positives.

**Technical:** end-to-end latency, API latency, tokens/scan, retries, refusal rate and abstention rate.

**Business:** cost per scan, manual testing time vs automated time, time saved, and evidence quality for a ship/no-ship decision.

The PRD targets a meaningful scan in ≤10 minutes; individual API calls have a 30-second timeout with up to two retries. fileciteturn6file1L116-L146 Token economics must account for input/output tokens, reasoning tokens where applicable, retries and repeated samples. fileciteturn6file4L379-L392

## 6. API Limits & Safety

PromptRed will enforce:
- maximum attacks per scan
- 1/3-turn limit
- maximum output/context tokens
- request timeout
- bounded retries with exponential backoff
- API-budget/cost guard
- graceful rate-limit/refusal handling
- no API keys in source or logs

The MVP uses user-provided prompts and synthetic target configuration only. It does not discover or connect to arbitrary external targets. Synthetic data is used for benchmarks/demos, and outputs identify the tool as intended for authorized defensive testing. fileciteturn6file1L122-L146

## 7. Professor Review → Required Changes

The professor's assessment is positive but says the proposal is under-specified. The project must therefore:

- Validate the **judge itself** with human labels, precision/recall/F1 and blind testing.
- Correct the metric contradiction between recall and false-negative rate.
- Use public injection datasets/seeds as a reality check rather than relying only on generated attacks.
- Explain agent/tool failure modes and multi-turn trajectories.
- Include token economics, latency and cost-to-serve.
- Ground remediation in recognized industry guidance such as OWASP.
- Quantify ROI/business value.
- Avoid claiming that existing industry testing does not exist; position PromptRed against existing approaches.
- Clarify alignment with OWASP LLM application security risks.
- Define the deliverable as a concrete MVP rather than a date-driven outcome.
- Maintain strong spelling, grammar and coherence.

The revised PRD already incorporates deterministic evidence, explicit synthetic business controls, and the principle that the LLM is a component rather than the security boundary. fileciteturn7file3L191-L216 fileciteturn7file6L375-L405

## 8. Final MVP Definition

> **Given a synthetic SaaS support system prompt and target configuration, PromptRed automatically generates and executes adversarial prompt-injection tests across four guardrails, detects and explains observable security failures, performs RCA, produces business-risk findings, and demonstrates that its LLM judge has been quantitatively evaluated against human ground truth.**

The core scanner must work without RAG or the UI. ChromaDB attack memory and Streamlit are enhancements. The final system should be CLI-runnable and Docker-deployable, with architecture suitable for a future CI/CD security gate, while CI/CD integration itself remains outside MVP scope. The revised PRD also keeps production monitoring, multilingual/multimodal testing and compliance certification outside MVP. fileciteturn7file6L406-L434
