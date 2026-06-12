"""Deterministic policy layer.

Everything in this module is a pure function: no LLM, no network, no I/O.
This is where the security-relevant decisions live, on purpose — the LLM can
*propose*, but code *disposes*:

  - severity has a code-computed floor the LLM cannot lower,
  - confidence is computed from observed degradations, not model vibes,
  - claimed CVE matches are verified against what the tool actually returned.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "starter-repo" / "risk_summary.schema.json"

SEVERITIES = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# --- Error taxonomy -----------------------------------------------------------
# The schema requires `errors` to be an array of strings; we use the convention
# "<code>: <detail>" so tests can assert on the stable code prefix.

E_EXTRACTION = "extraction_partial"
E_TOOL = "tool_failure"
E_NO_CVE = "no_cve_data"
E_INJECTION = "prompt_injection_detected"
E_LLM = "llm_error"
E_CONFLICT = "severity_conflict"
E_HALLUCINATED = "hallucinated_cve_dropped"
E_MISMATCH = "product_name_mismatch"
E_LEAK = "injection_leakage_blocked"
E_SCHEMA = "schema_validation_failed"

# Weight = how much an error class degrades trust in the summary.
# extraction/llm failures are weighted double: if we could not even read the
# advisory reliably, everything downstream inherits that doubt.
_ERROR_WEIGHTS = {
    E_EXTRACTION: 2,
    E_LLM: 2,
    E_TOOL: 1,
    E_NO_CVE: 1,
    E_INJECTION: 1,
    E_CONFLICT: 1,
    E_HALLUCINATED: 1,
    E_MISMATCH: 1,
    E_LEAK: 1,
    E_SCHEMA: 1,
}


def error_entry(code: str, detail: str) -> str:
    detail = " ".join(detail.split())  # collapse whitespace/newlines
    return f"{code}: {detail}"


def error_code(entry: str) -> str:
    return entry.split(":", 1)[0]


# --- Severity -----------------------------------------------------------------

def severity_rank(severity: str) -> int:
    return _SEV_RANK.get(severity, -1)


def severity_floor(
    selected_cve_ids: list[str],
    cve_severity_by_id: dict[str, str],
    injection_detected: bool,
) -> str:
    """Code-computed lower bound for overall severity.

    - The floor is the max severity among the *relevant* CVEs, taken from the
      tool's own records (keyed by CVE id), so the LLM cannot spoof the values.
    - An advisory carrying an active manipulation attempt is never treated as
      no-risk: injection raises the floor to at least MEDIUM. This is the rule
      that holds even in the worst corner (injection present AND the lookup
      tool down, so no CVE evidence exists).
    """
    floor = "NONE"
    for cve_id in selected_cve_ids:
        sev = cve_severity_by_id.get(cve_id)
        if sev and severity_rank(sev) > severity_rank(floor):
            floor = sev
    if injection_detected and severity_rank(floor) < severity_rank("MEDIUM"):
        floor = "MEDIUM"
    return floor


def assessment_failure_floor(
    floor: str, all_returned_severities: dict[str, str]
) -> str:
    """Floor used when the assessment stage produced no usable severity.

    A failed/degraded assessment must never read as "no risk": the floor falls
    back to the max severity among ALL CVEs the tool returned (the model's
    relevance selection no longer exists to narrow it — conservative by
    construction), and never below MEDIUM, consistent with fallback_summary.
    """
    for sev in all_returned_severities.values():
        if severity_rank(sev) > severity_rank(floor):
            floor = sev
    if severity_rank(floor) < severity_rank("MEDIUM"):
        floor = "MEDIUM"
    return floor


def apply_severity_floor(proposed: str | None, floor: str) -> tuple[str, bool]:
    """Final severity = proposed, unless below the floor. LLM may raise (with
    its rationale), may never lower below evidence. Returns (severity, conflicted).
    """
    if proposed not in _SEV_RANK:
        return floor, proposed is not None
    if severity_rank(proposed) < severity_rank(floor):
        return floor, True
    return proposed, False


def filter_hallucinated_cves(
    claimed_ids: list[str], returned_ids: set[str]
) -> tuple[list[str], list[str]]:
    """Keep only CVE ids the tool actually returned. Returns (kept, dropped)."""
    kept, dropped = [], []
    for cid in claimed_ids:
        (kept if cid in returned_ids else dropped).append(cid)
    return kept, dropped


# --- Confidence ---------------------------------------------------------------

def confidence_ceiling(errors: list[str]) -> float:
    """Deterministic trust ceiling from observed degradations.

    weight 0  -> 0.9  (clean run)
    weight 1  -> 0.6  (exactly one simple degradation)
    weight 2+ -> 0.3  (malformed input, LLM failure, or compounding problems)
    """
    total = sum(_ERROR_WEIGHTS.get(error_code(e), 1) for e in errors)
    if total == 0:
        return 0.9
    if total == 1:
        return 0.6
    return 0.3


def final_confidence(suggestion: Any, ceiling: float) -> float:
    """LLM may suggest a confidence; code clamps it to [0.05, ceiling]."""
    try:
        value = float(suggestion)
    except (TypeError, ValueError):
        return ceiling
    return round(min(max(value, 0.05), ceiling), 2)


# --- Output assembly & schema validation ---------------------------------------

_validator: Draft7Validator | None = None


def schema_validator() -> Draft7Validator:
    global _validator
    if _validator is None:
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            _validator = Draft7Validator(json.load(fh))
    return _validator


def validate_summary(summary: dict) -> list[str]:
    """Validate against the *provided* schema file. Returns list of problems."""
    return [e.message for e in schema_validator().iter_errors(summary)]


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "advisory"


def fallback_summary(advisory_id: str, errors: list[str]) -> dict:
    """Minimal schema-valid object emitted only if assembly itself fails.
    The pipeline must always return *something* an analyst can act on."""
    return {
        "advisory_id": advisory_id,
        "affected_products": [],
        "overall_severity": "MEDIUM",
        "confidence": 0.05,
        "recommended_action": (
            "Automated triage degraded; route this advisory to a human analyst."
        ),
        "rationale": (
            "The triage pipeline could not produce a grounded assessment "
            "(see errors). Severity defaults to MEDIUM pending manual review."
        ),
        "errors": errors,
    }
