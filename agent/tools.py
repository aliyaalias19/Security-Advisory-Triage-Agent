"""Wrapper around the provided mock tool (starter-repo/cve_lookup.py).

The starter repo is imported as-is and never modified. This module owns:
  - bounded retry with exponential backoff + jitter for the flaky upstream,
  - sanitization of tool output before it is shown to the LLM (tool results
    are third-party text in production — same trust rules as the advisory).
"""

from __future__ import annotations

import random
import string
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "starter-repo"))

from cve_lookup import CVELookupError, lookup_cves  # noqa: E402

MAX_ATTEMPTS = 3
BASE_DELAY_S = 0.4

_PRINTABLE = set(string.printable)


def lookup_with_retry(
    product: str,
    version: str | None = None,
    *,
    max_attempts: int = MAX_ATTEMPTS,
    base_delay: float = BASE_DELAY_S,
    sleep=time.sleep,
    lookup=lookup_cves,
) -> tuple[list[dict] | None, str | None]:
    """Call the lookup tool with bounded retries.

    Returns (records, None) on success — records may be an empty list —
    or (None, error_detail) once all attempts are exhausted.
    `sleep` and `lookup` are injectable for deterministic tests.
    """
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return lookup(product, version), None
        except CVELookupError as exc:
            last_exc = exc
            if attempt < max_attempts:
                sleep(base_delay * (2 ** (attempt - 1)) * (1 + random.random() * 0.25))
        except Exception as exc:  # undocumented tool failure: degrade, don't retry
            return None, (
                f"lookup_cves({product!r}) raised unexpected "
                f"{type(exc).__name__}: {exc}"
            )
    return None, f"lookup_cves({product!r}) failed after {max_attempts} attempts: {last_exc}"


def sanitize_records(records: list[dict], summary_max_len: int = 300) -> list[dict]:
    """Reduce tool records to known fields, strip non-printable characters and
    truncate free text. In production, CVE descriptions are untrusted
    third-party text and a second injection surface — same handling applies."""
    out = []
    for rec in records:
        fixed_in = rec.get("fixed_in")
        cvss = rec.get("cvss")
        out.append(
            {
                "cve_id": _clean(str(rec.get("cve_id", "")), 60),
                "cvss": float(cvss) if isinstance(cvss, (int, float)) else None,
                "severity": _clean(str(rec.get("severity", "")), 16),
                "summary": _clean(str(rec.get("summary", "")), summary_max_len),
                "affected_versions": _clean(str(rec.get("affected_versions", "")), 100),
                "fixed_in": _clean(str(fixed_in), 60) if fixed_in else None,
            }
        )
    return out


def _clean(text: str, max_len: int) -> str:
    cleaned = "".join(ch for ch in text if ch in _PRINTABLE)
    return cleaned[:max_len].strip()
