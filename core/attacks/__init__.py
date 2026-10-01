"""Attack side: generating attacks and running them against the target.

generator.py writes attacks with a rented LLM, harness.py runs 1- or 3-turn
conversations, benchmark.py loads the synthetic benchmark prompts, and
strategies/ decides which attacks to try for each guardrail category.
"""
