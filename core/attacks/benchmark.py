"""Load PromptRed benchmark prompts."""

import json
from pathlib import Path


class BenchmarkLoader:
    """Loads the synthetic PromptRed benchmark."""

    def __init__(
        self,
        path: str = (
            "data/benchmarks/"
            "known_vulnerable_prompts.json"
        ),
    ):
        self.path = Path(path)

    def load(self) -> list[dict]:
        """Load all benchmark prompts."""

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        return data["prompts"]

    def get_prompt(
        self,
        prompt_id: str,
    ) -> dict:
        """Return one benchmark prompt by ID."""

        prompts = self.load()

        for prompt in prompts:
            if prompt["id"] == prompt_id:
                return prompt

        raise ValueError(
            f"Benchmark prompt not found: {prompt_id}"
        )