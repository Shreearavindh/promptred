"""System prompt discovery for PromptRed.

Manually copy-pasting a system prompt into the CLI doesn't scale and
doesn't match the intended MVP workflow: point PromptRed at a target
project directory and let it find what's actually deployed. This
scanner walks a directory, extracts candidate system-prompt strings
using layered heuristics (cheap pattern match first, optional LLM
confirmation for low-confidence hits), and dedupes near-identical
prompts found in multiple files.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Protocol

import yaml

SCANNABLE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".yaml",
    ".yml",
    ".json",
    ".md",
    ".txt",
}

SKIP_DIRS = {
    "node_modules",
    ".venv",
    "venv",
    ".git",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
}

MIN_PROMPT_LENGTH = 40

INSTRUCTIONAL_KEYWORDS = [
    "you are",
    "assistant",
    "must not",
    "never",
    "always",
    "do not",
    "should not",
]

CONFIG_KEY_NAMES = {
    "system_prompt",
    "instructions",
    "persona",
    "system_message",
}

_CODE_STRING_PATTERNS = [
    re.compile(
        r'"""(?P<content>You are .+?)"""',
        re.DOTALL | re.IGNORECASE,
    ),
    re.compile(
        r"'''(?P<content>You are .+?)'''",
        re.DOTALL | re.IGNORECASE,
    ),
    re.compile(
        r'(?:SYSTEM_PROMPT|system_prompt)\s*[:=]\s*f?'
        r'(?P<quote>["\'])'
        r'(?P<content>(?:\\.|(?!(?P=quote)).){40,})'
        r'(?P=quote)',
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r'["\']role["\']\s*:\s*["\']system["\']\s*,\s*["\']content'
        r'["\']\s*:\s*(?P<quote>["\'])'
        r'(?P<content>(?:\\.|(?!(?P=quote)).){40,})'
        r'(?P=quote)',
        re.IGNORECASE | re.DOTALL,
    ),
]


@dataclass
class DiscoveredPrompt:
    """One candidate system prompt found in a target project."""

    file_path: str
    line_number: int
    prompt_text: str
    confidence: float
    extraction_method: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "prompt_text": self.prompt_text,
            "confidence": self.confidence,
            "extraction_method": self.extraction_method,
        }


class ConfirmationClient(Protocol):
    def generate_messages(self, messages: list[dict[str, str]]) -> str:
        ...


def _looks_instructional(text: str) -> bool:
    if len(text) < MIN_PROMPT_LENGTH:
        return False

    text_lower = text.lower()
    return any(
        keyword in text_lower for keyword in INSTRUCTIONAL_KEYWORDS
    )


def _line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


class PromptScanner:
    """Discovers candidate system prompts in a target project directory."""

    def __init__(
        self,
        use_llm_confirmation: bool = False,
        llm_client: ConfirmationClient | None = None,
        confirmation_threshold: float = 0.8,
    ) -> None:
        self.use_llm_confirmation = use_llm_confirmation
        self.confirmation_threshold = confirmation_threshold

        if use_llm_confirmation and llm_client is None:
            from core.llm.client import LLMClient
            from core.llm.roles import ModelRole

            llm_client = LLMClient(role=ModelRole.ATTACKER)

        self.llm_client = llm_client

    def scan(self, root_path: str | Path) -> list[DiscoveredPrompt]:
        """Walk root_path and return deduped discovered prompts."""

        root = Path(root_path)
        candidates: list[DiscoveredPrompt] = []

        for file_path in self._iter_scannable_files(root):
            candidates.extend(self._scan_file(file_path))

        deduped = self._dedupe(candidates)

        if self.use_llm_confirmation:
            deduped = [
                (
                    self.confirm_with_llm(candidate)
                    if candidate.confidence
                    < self.confirmation_threshold
                    else candidate
                )
                for candidate in deduped
            ]

        return deduped

    def confirm_with_llm(
        self,
        candidate: DiscoveredPrompt,
    ) -> DiscoveredPrompt:
        """Adjust confidence using an LLM judgment on a low-confidence hit."""

        if self.llm_client is None:
            return candidate

        prompt = f"""
Is the following text a system prompt / operating instructions for an
AI assistant (as opposed to unrelated code, documentation, or
comments)? Answer with ONLY "yes" or "no".

Text:
---
{candidate.prompt_text}
---
""".strip()

        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Answer now."},
        ]

        try:
            raw_response = self.llm_client.generate_messages(messages)
        except Exception:
            return candidate

        answer = raw_response.strip().lower()

        if answer.startswith("yes"):
            confidence = min(1.0, candidate.confidence + 0.1)
        elif answer.startswith("no"):
            confidence = max(0.0, candidate.confidence - 0.4)
        else:
            confidence = candidate.confidence

        return DiscoveredPrompt(
            file_path=candidate.file_path,
            line_number=candidate.line_number,
            prompt_text=candidate.prompt_text,
            confidence=confidence,
            extraction_method=(
                candidate.extraction_method + "+llm_confirmed"
            ),
        )

    def _iter_scannable_files(self, root: Path) -> Iterator[Path]:
        for path in root.rglob("*"):
            if not path.is_file():
                continue

            if path.suffix.lower() not in SCANNABLE_EXTENSIONS:
                continue

            if any(part in SKIP_DIRS for part in path.parts):
                continue

            yield path

    def _scan_file(self, file_path: Path) -> list[DiscoveredPrompt]:
        try:
            text = file_path.read_text(
                encoding="utf-8", errors="ignore"
            )
        except OSError:
            return []

        if file_path.suffix.lower() in {".yaml", ".yml", ".json"}:
            return self._scan_config_file(file_path, text)

        return self._scan_code_file(file_path, text)

    def _scan_code_file(
        self,
        file_path: Path,
        text: str,
    ) -> list[DiscoveredPrompt]:
        found: list[DiscoveredPrompt] = []

        for pattern in _CODE_STRING_PATTERNS:
            for match in pattern.finditer(text):
                content = match.group("content").strip()

                if not _looks_instructional(content):
                    continue

                found.append(
                    DiscoveredPrompt(
                        file_path=str(file_path),
                        line_number=_line_number_for_offset(
                            text, match.start()
                        ),
                        prompt_text=content,
                        confidence=0.85,
                        extraction_method="code_pattern",
                    )
                )

        return found

    def _scan_config_file(
        self,
        file_path: Path,
        text: str,
    ) -> list[DiscoveredPrompt]:
        found: list[DiscoveredPrompt] = []

        try:
            if file_path.suffix.lower() == ".json":
                data = json.loads(text)
            else:
                data = yaml.safe_load(text)
        except Exception:
            return []

        for key, value in self._walk_keys(data):
            if key not in CONFIG_KEY_NAMES:
                continue

            if not isinstance(value, str) or not _looks_instructional(
                value
            ):
                continue

            found.append(
                DiscoveredPrompt(
                    file_path=str(file_path),
                    line_number=1,
                    prompt_text=value,
                    confidence=0.9,
                    extraction_method="config_key",
                )
            )

        return found

    def _walk_keys(
        self,
        data: Any,
    ) -> Iterator[tuple[Any, Any]]:
        if isinstance(data, dict):
            for key, value in data.items():
                yield key, value
                yield from self._walk_keys(value)
        elif isinstance(data, list):
            for item in data:
                yield from self._walk_keys(item)

    @staticmethod
    def _dedupe(
        candidates: list[DiscoveredPrompt],
    ) -> list[DiscoveredPrompt]:
        seen: dict[str, DiscoveredPrompt] = {}

        for candidate in candidates:
            key = re.sub(
                r"\s+", " ", candidate.prompt_text.strip().lower()
            )[:200]

            if (
                key not in seen
                or candidate.confidence > seen[key].confidence
            ):
                seen[key] = candidate

        return list(seen.values())
