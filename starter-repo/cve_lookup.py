"""
Mock CVE lookup "tool" for the take-home assessment.

This stands in for a real vulnerability database (NVD, vendor feeds, etc.).
It is deliberately offline and deterministic so the exercise has no external
dependencies. Treat the `lookup_cves` function as the underlying capability you
will expose to your agent as a tool / function call.

Notes that mirror real-world tools:
  - Lookups are by (product, version). Matching is loose on purpose.
  - Some queries return multiple CVEs; some return none.
  - The tool can RAISE (simulating a transient API failure) for one product.
    Your agent is expected to handle this gracefully, not crash.
  - The data here is fictional. Do not treat CVE IDs as real.
"""

from __future__ import annotations

import random
from typing import TypedDict


class CVERecord(TypedDict):
    cve_id: str
    cvss: float            # 0.0 - 10.0
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    summary: str
    affected_versions: str
    fixed_in: str | None


# Fictional database keyed by lowercased product name.
_DB: dict[str, list[CVERecord]] = {
    "openssl": [
        {
            "cve_id": "CVE-2099-1001",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "summary": "Heap buffer overflow in the TLS handshake allowing remote code execution.",
            "affected_versions": "3.0.0 - 3.0.6",
            "fixed_in": "3.0.7",
        },
        {
            "cve_id": "CVE-2099-1002",
            "cvss": 5.9,
            "severity": "MEDIUM",
            "summary": "Timing side-channel in RSA decryption.",
            "affected_versions": "1.1.1 - 1.1.1t",
            "fixed_in": "1.1.1u",
        },
    ],
    "nginx": [
        {
            "cve_id": "CVE-2099-2001",
            "cvss": 7.5,
            "severity": "HIGH",
            "summary": "Denial of service via crafted HTTP/2 frames.",
            "affected_versions": "1.20.0 - 1.24.0",
            "fixed_in": "1.25.0",
        },
    ],
    "log4j": [
        {
            "cve_id": "CVE-2099-3001",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "summary": "Remote code execution via JNDI lookup in log message substitution.",
            "affected_versions": "2.0 - 2.14.1",
            "fixed_in": "2.15.0",
        },
        {
            "cve_id": "CVE-2099-3002",
            "cvss": 9.0,
            "severity": "CRITICAL",
            "summary": "Incomplete fix for the JNDI lookup issue under non-default configs.",
            "affected_versions": "2.15.0",
            "fixed_in": "2.16.0",
        },
    ],
    "postgresql": [
        {
            "cve_id": "CVE-2099-4001",
            "cvss": 4.3,
            "severity": "MEDIUM",
            "summary": "Information disclosure through error messages in certain queries.",
            "affected_versions": "14.0 - 14.8",
            "fixed_in": "14.9",
        },
    ],
    # "redis" intentionally simulates a flaky upstream — see below.
    "redis": [
        {
            "cve_id": "CVE-2099-5001",
            "cvss": 8.1,
            "severity": "HIGH",
            "summary": "Lua sandbox escape leading to arbitrary command execution.",
            "affected_versions": "6.0.0 - 7.0.4",
            "fixed_in": "7.0.5",
        },
    ],
}


class CVELookupError(RuntimeError):
    """Raised to simulate a transient upstream failure."""


def lookup_cves(product: str, version: str | None = None) -> list[CVERecord]:
    """
    Look up known CVEs for a product (and optional version).

    Args:
        product: Product name, e.g. "OpenSSL". Case-insensitive.
        version: Optional version string. Currently used only loosely — the
                 mock returns all records for the product and leaves
                 version-range reasoning to the caller (your agent).

    Returns:
        A list of CVERecord dicts. May be empty if nothing is known.

    Raises:
        CVELookupError: Randomly, ~40% of the time, for the product "redis"
                        only — to simulate a flaky upstream API. Your agent
                        should handle this (retry and/or degrade gracefully).
    """
    key = (product or "").strip().lower()

    # Simulate a flaky upstream for one product so candidates must handle errors.
    if key == "redis" and random.random() < 0.4:
        raise CVELookupError("Upstream CVE service timed out (simulated).")

    return _DB.get(key, [])


if __name__ == "__main__":
    # Quick manual check.
    for p in ["OpenSSL", "nginx", "Log4j", "UnknownProduct"]:
        print(p, "->", [c["cve_id"] for c in lookup_cves(p)])
