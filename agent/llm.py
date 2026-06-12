"""LLM provider boundary.

One class talks to the Anthropic API; everything else in the pipeline depends
only on the `.complete(system, user) -> str` interface, so swapping providers
(or injecting a fake for tests) touches exactly this seam.

`complete_json` owns the "model output must be valid, validated JSON" loop:
parse -> validate -> on failure, re-prompt once with the concrete problem ->
give up cleanly with LLMError so the pipeline can degrade instead of crash.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from typing import Protocol


class LLMError(RuntimeError):
    """The model could not produce usable output within the retry budget."""


class LLM(Protocol):
    def complete(self, system: str, user: str) -> str: ...


# claude-sonnet-4-x (May 2025) was retired mid-build (EOL 2026-06-15) and
# began returning intermittent not_found errors — the pipeline degraded
# gracefully as designed, but the default must point at a current model.
DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicLLM:
    def __init__(self, model: str | None = None, max_tokens: int = 2000):
        import anthropic  # imported lazily so unit tests need no SDK/key

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise LLMError(
                "ANTHROPIC_API_KEY is not set. Export it before running live."
            )
        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model or os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)
        self.max_tokens = max_tokens

    def complete(self, system: str, user: str) -> str:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=0,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in response.content if b.type == "text")


def parse_json_object(text: str) -> dict:
    """Extract the first JSON object from model output, tolerating code fences
    and surrounding prose. Raises ValueError if none parses."""
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        if candidate.lower().startswith("json"):
            candidate = candidate[4:]
    try:
        obj = json.loads(candidate)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        obj = json.loads(text[start : end + 1])
        if isinstance(obj, dict):
            return obj
    raise ValueError("no JSON object found in model output")


def complete_json(
    llm: LLM,
    system: str,
    user: str,
    validate: Callable[[dict], list[str]],
    max_attempts: int = 3,
) -> dict:
    """Call the model, parse + validate JSON, and re-prompt with the concrete
    validation errors on failure. Raises LLMError after max_attempts."""
    prompt = user
    problems: list[str] = []
    for attempt in range(1, max_attempts + 1):
        try:
            raw = llm.complete(system, prompt)
        except LLMError:
            raise
        except Exception as exc:  # network/SDK errors degrade, never crash
            problems = [f"provider error: {exc}"]
            if attempt < max_attempts:
                time.sleep(0.5 * attempt)
            continue
        try:
            obj = parse_json_object(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            problems = [f"output was not valid JSON: {exc}"]
        else:
            problems = validate(obj)
            if not problems:
                return obj
        prompt = (
            user
            + "\n\nYour previous response was rejected for these reasons:\n- "
            + "\n- ".join(problems)
            + "\nRespond again with ONLY a corrected JSON object."
        )
    raise LLMError("; ".join(problems) or "unknown LLM failure")
