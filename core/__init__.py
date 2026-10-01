"""PromptRed core: attack generation, target bot, evaluation, scoring, remediation, reporting.

Data flow: discovery -> attacks (strategies + generator + harness) -> target_bot
-> evidence -> evaluator (rules, LLM judge, calibrated abstention, judge panel)
-> scoring (severity, root cause) -> remediation (OWASP 2026) -> reporting.
core/orchestrator.py wires these together for one scan.
"""
