"""Guardrails that keep PromptRed a testing tool rather than an attack tool.

attack_scope.py refuses generated attacks outside the four business
guardrails PromptRed tests. The volume ceiling lives in promptred.py
(MAX_ATTACKS_PER_RUN) and report redaction in core/reporting/.
"""
