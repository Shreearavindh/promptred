"""Shared JSON-response parsing helpers for LLM output.

Chat-tuned models frequently wrap JSON output in a markdown code
fence (```json ... ```) even when explicitly instructed to return
JSON only and nothing else - fencing code/JSON blocks is deeply
trained formatting behavior that a prompt instruction doesn't
reliably suppress. Both the attack generator and the judge parse a
JSON response from the model, so this fence-stripping lives here once
rather than being duplicated (and potentially drifting) in both
places.
"""

import re

_FENCE_PATTERN = re.compile(
    r"^```(?:json)?\s*\n?(?P<body>.*?)\n?```$",
    re.DOTALL | re.IGNORECASE,
)


def strip_json_fence(text: str) -> str:
    """Strip a wrapping ```json ... ``` (or plain ``` ... ```) fence.

    Returns the original (whitespace-trimmed) text unchanged if it
    isn't fully wrapped in a fence, so this is always safe to apply
    before json.loads() - it never *removes* content that a stricter
    parse would have accepted, it only helps with the fenced case.
    """

    stripped = text.strip()
    match = _FENCE_PATTERN.match(stripped)

    if match:
        return match.group("body").strip()

    return stripped
