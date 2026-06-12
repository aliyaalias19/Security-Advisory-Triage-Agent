"""Smoke tests for the CLI layer (triage.py main): arg handling, output
writing, per-file failure isolation, and exit codes. The pipeline beneath is
covered elsewhere; these pin the one layer that previously had no tests."""

import json
import sys

import triage as cli
from agent.llm import LLMError


class FakeLLM:
    """Minimal scripted double for AnthropicLLM inside the CLI."""

    def __init__(self):
        self.responses = [
            json.dumps({"advisory_id": "ADV-2099-0007",
                        "products": [{"product": "OpenSSL",
                                      "version": "3.0.0 - 3.0.6"}],
                        "malformed": False, "malformed_reason": None}),
            json.dumps({"per_product": [{"product": "OpenSSL",
                                         "relevant_cve_ids": ["CVE-2099-1001"]}],
                        "overall_severity": "CRITICAL",
                        "recommended_action": "Upgrade to 3.0.7.",
                        "rationale": "Range matches CVE-2099-1001.",
                        "confidence": 0.9, "embedded_instructions": None}),
        ]

    def complete(self, system, user):
        if not self.responses:
            raise LLMError("fake exhausted")
        return self.responses.pop(0)


def test_cli_single_advisory_writes_output_and_exits_zero(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(cli, "AnthropicLLM", lambda: FakeLLM())
    monkeypatch.setattr(sys, "argv", [
        "triage.py",
        "starter-repo/advisories/01_clean_single_product.txt",
        "--out", str(tmp_path),
    ])
    assert cli.main() == 0
    written = json.loads(
        (tmp_path / "01_clean_single_product.json").read_text(encoding="utf-8")
    )
    assert written["overall_severity"] == "CRITICAL"
    assert "01_clean_single_product.txt" in capsys.readouterr().out


def test_cli_missing_file_fails_that_file_but_keeps_running(
    monkeypatch, tmp_path, capsys
):
    """One bad path must not abort the run: the good advisory after it is
    still processed, and the exit code reports the failure."""
    monkeypatch.setattr(cli, "AnthropicLLM", lambda: FakeLLM())
    monkeypatch.setattr(sys, "argv", [
        "triage.py",
        "does_not_exist.txt",
        "starter-repo/advisories/01_clean_single_product.txt",
        "--out", str(tmp_path),
    ])
    assert cli.main() == 1                       # failure surfaced
    assert (tmp_path / "01_clean_single_product.json").exists()  # work continued
    assert "does_not_exist.txt" in capsys.readouterr().err
