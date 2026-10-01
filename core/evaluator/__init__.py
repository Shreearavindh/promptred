"""Decides whether a guardrail broke.

deterministic.py (rules, checked first), llm_judge.py (rubric judge with
untrusted text fenced off), selective_evaluation.py (calibrated confidence
threshold), judge_panel.py (second judge on low confidence) and pipeline.py
(runs them in order; anything still uncertain goes to human review).
"""
