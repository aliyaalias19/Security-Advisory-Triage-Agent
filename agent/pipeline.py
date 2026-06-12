"""Pipeline orchestration.

Deterministic control flow; the LLM is invoked at exactly two points
(extraction, assessment). Code — never the model — decides when the lookup
tool is called and with what arguments, which is the structural defense
against prompt injection. Every failure mode degrades into the `errors`
array and a lower confidence; the pipeline always returns a schema-valid
object and never raises for bad input, flaky tools, or a failing model.
"""

from __future__ import annotations

from . import injection, policy, prompts, tools
from .llm import LLM, LLMError, complete_json

MAX_PRODUCTS = 10


def triage(
    advisory_text: str,
    fallback_advisory_id: str,
    llm: LLM,
    *,
    lookup=None,
    sleep=None,
) -> dict:
    """Run the full triage pipeline on one advisory. Always returns a dict
    that validates against starter-repo/risk_summary.schema.json."""
    errors: list[str] = []
    lookup_kwargs = {}
    if lookup is not None:
        lookup_kwargs["lookup"] = lookup
    if sleep is not None:
        lookup_kwargs["sleep"] = sleep

    # 1. Injection heuristics — on the raw text, before any LLM sees it.
    injected_lines = injection.detect_injection(advisory_text)
    if injected_lines:
        errors.append(
            policy.error_entry(
                policy.E_INJECTION,
                f"injected instructions ignored: {injected_lines[0][:120]!r}",
            )
        )

    # 2. Extraction (LLM call 1).
    extraction = _run_extraction(advisory_text, llm, errors)
    products = extraction["products"]
    advisory_id = extraction["advisory_id"] or policy.slugify(fallback_advisory_id)

    # 3. CVE lookups — code-driven, deduped, retried.
    evidence, returned_ids, severity_by_id = _run_lookups(
        products, errors, lookup_kwargs
    )

    # 4. Assessment (LLM call 2).
    assessment = _run_assessment(advisory_text, evidence, llm, errors)

    # 5. Policy: verify CVE claims, floor severity, scrub leakage.
    matched_by_product = _verified_matches(
        assessment.get("per_product"), products, returned_ids, errors
    )
    all_selected = [cid for ids in matched_by_product.values() for cid in ids]

    embedded = assessment.get("embedded_instructions")
    if embedded and not injected_lines:
        errors.append(
            policy.error_entry(
                policy.E_INJECTION, f"model-reported attempt: {str(embedded)[:120]!r}"
            )
        )
    injection_detected = bool(injected_lines or embedded)

    floor = policy.severity_floor(all_selected, severity_by_id, injection_detected)
    proposed = assessment.get("overall_severity")
    if proposed not in policy.SEVERITIES:
        # Assessment failed or returned garbage: degrade conservatively. The
        # model's relevance selection is gone, so the floor falls back to ALL
        # returned CVE evidence, and never below MEDIUM.
        floor = policy.assessment_failure_floor(floor, severity_by_id)
    severity, conflicted = policy.apply_severity_floor(proposed, floor)
    if conflicted:
        errors.append(
            policy.error_entry(
                policy.E_CONFLICT,
                f"proposed severity {proposed!r} was below "
                f"the evidence-derived floor {floor}; floor applied",
            )
        )

    action = str(assessment.get("recommended_action") or "").strip()
    rationale = str(assessment.get("rationale") or "").strip()
    scrub_sources = list(injected_lines)
    if embedded:  # model-reported attempt: scrub its quoted payloads too,
        # even when the heuristics missed the injection entirely
        scrub_sources += injection.quoted_payloads(str(embedded))
    if scrub_sources:
        leaked = injection.find_leakage(
            f"{action}\n{rationale}", scrub_sources, advisory_text
        )
        if leaked:
            action = injection.scrub(action, leaked)
            rationale = injection.scrub(rationale, leaked)
            errors.append(
                policy.error_entry(
                    policy.E_LEAK,
                    f"removed injected fragment(s) from output: {leaked[0][:80]!r}",
                )
            )

    # 6. Assemble, compute confidence, validate against the provided schema.
    summary = {
        "advisory_id": advisory_id,
        "affected_products": [
            {
                "product": p["product"],
                "version": p["version"],
                "matched_cves": matched_by_product.get(p["product"].lower(), []),
            }
            for p in products
        ],
        "overall_severity": severity,
        "confidence": policy.final_confidence(
            assessment.get("confidence"), policy.confidence_ceiling(errors)
        ),
        "recommended_action": action
        or "Route this advisory to a human analyst for manual triage.",
        "rationale": rationale
        or "Automated assessment degraded; see errors for details.",
        "errors": errors,
    }

    problems = policy.validate_summary(summary)
    if problems:
        errors.append(
            policy.error_entry(policy.E_SCHEMA, "; ".join(problems)[:200])
        )
        return policy.fallback_summary(advisory_id, errors)
    return summary


# --- stages -------------------------------------------------------------------


def _run_extraction(advisory_text: str, llm: LLM, errors: list[str]) -> dict:
    def validate(obj: dict) -> list[str]:
        problems = []
        prods = obj.get("products")
        if not isinstance(prods, list):
            problems.append('"products" must be a list')
        else:
            for item in prods:
                if not isinstance(item, dict) or not str(item.get("product", "")).strip():
                    problems.append("each product needs a non-empty 'product' string")
                    break
        return problems

    try:
        raw = complete_json(
            llm,
            prompts.EXTRACTION_SYSTEM,
            prompts.extraction_user(advisory_text),
            validate,
        )
    except LLMError as exc:
        errors.append(policy.error_entry(policy.E_LLM, f"extraction failed: {exc}"))
        errors.append(
            policy.error_entry(
                policy.E_EXTRACTION, "no products could be extracted; manual review needed"
            )
        )
        return {"advisory_id": None, "products": []}

    if raw.get("malformed"):
        reason = raw.get("malformed_reason") or "advisory is incomplete or garbled"
        errors.append(policy.error_entry(policy.E_EXTRACTION, str(reason)[:200]))

    seen: set[str] = set()
    products: list[dict] = []
    for item in raw.get("products", []):
        name = str(item.get("product", "")).strip()
        key = name.lower()
        if not name or key in seen:
            continue
        seen.add(key)
        version = item.get("version")
        products.append(
            {"product": name, "version": str(version).strip() if version else None}
        )
        if len(products) >= MAX_PRODUCTS:
            break

    adv_id = raw.get("advisory_id")
    return {
        "advisory_id": str(adv_id).strip() if adv_id else None,
        "products": products,
    }


def _run_lookups(
    products: list[dict], errors: list[str], lookup_kwargs: dict
) -> tuple[list[dict], set[str], dict[str, str]]:
    evidence: list[dict] = []
    returned_ids: set[str] = set()
    severity_by_id: dict[str, str] = {}
    any_success, any_cves = False, False

    for p in products:
        records, failure = tools.lookup_with_retry(
            p["product"], p["version"], **lookup_kwargs
        )
        if failure is not None:
            errors.append(policy.error_entry(policy.E_TOOL, failure))
            evidence.append(
                {
                    "product": p["product"],
                    "version_in_advisory": p["version"],
                    "lookup_status": "FAILED after retries — no CVE data available",
                    "cves": [],
                }
            )
            continue
        any_success = True
        clean = tools.sanitize_records(records)
        if clean:
            any_cves = True
        for rec in clean:
            returned_ids.add(rec["cve_id"])
            severity_by_id[rec["cve_id"]] = rec["severity"]
        evidence.append(
            {
                "product": p["product"],
                "version_in_advisory": p["version"],
                "lookup_status": "ok",
                "cves": clean,
            }
        )

    if products and any_success and not any_cves:
        errors.append(
            policy.error_entry(
                policy.E_NO_CVE,
                "lookup returned no CVE records for any extracted product; "
                "severity reasoned from advisory text alone",
            )
        )
    return evidence, returned_ids, severity_by_id


def _run_assessment(
    advisory_text: str, evidence: list[dict], llm: LLM, errors: list[str]
) -> dict:
    def validate(obj: dict) -> list[str]:
        problems = []
        if obj.get("overall_severity") not in policy.SEVERITIES:
            problems.append(
                f'"overall_severity" must be one of {policy.SEVERITIES}'
            )
        for field in ("recommended_action", "rationale"):
            if not str(obj.get(field, "")).strip():
                problems.append(f'"{field}" must be a non-empty string')
        if not isinstance(obj.get("per_product", []), list):
            problems.append('"per_product" must be a list')
        return problems

    try:
        return complete_json(
            llm,
            prompts.ASSESSMENT_SYSTEM,
            prompts.assessment_user(advisory_text, evidence),
            validate,
        )
    except LLMError as exc:
        errors.append(policy.error_entry(policy.E_LLM, f"assessment failed: {exc}"))
        return {}


def _verified_matches(
    per_product, products: list[dict], returned_ids: set[str], errors: list[str]
) -> dict[str, list[str]]:
    """Map product (lowercased) -> verified relevant CVE ids. Any id the tool
    never returned is dropped and recorded — the model cannot launder
    invented CVEs into the output. Product names from the model are matched
    loosely (prefix, e.g. "Postgres" -> "postgresql") but only when the match
    is unambiguous; anything unmatched is recorded, never silently dropped."""
    known = {p["product"].lower() for p in products}
    matched: dict[str, list[str]] = {}
    dropped_all: list[str] = []
    unmatched: list[str] = []
    for entry in per_product or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("product", "")).strip()
        key = _resolve_product(name.lower(), known)
        claimed = [str(c) for c in entry.get("relevant_cve_ids", []) or []]
        if key is None:
            if name or claimed:
                unmatched.append(name or "<blank>")
            continue
        kept, dropped = policy.filter_hallucinated_cves(claimed, returned_ids)
        matched[key] = sorted(set(matched.get(key, [])) | set(kept))
        dropped_all.extend(dropped)
    if dropped_all:
        errors.append(
            policy.error_entry(
                policy.E_HALLUCINATED,
                f"model claimed CVEs the tool never returned: {sorted(set(dropped_all))}",
            )
        )
    if unmatched:
        errors.append(
            policy.error_entry(
                policy.E_MISMATCH,
                "model referenced product(s) not in the extracted set; their CVE "
                f"selections were discarded: {sorted(set(unmatched))}",
            )
        )
    return matched


def _resolve_product(key: str, known: set[str]) -> str | None:
    """Exact match, else unambiguous prefix match in either direction."""
    if key in known:
        return key
    if not key:
        return None
    candidates = [k for k in known if k.startswith(key) or key.startswith(k)]
    return candidates[0] if len(candidates) == 1 else None
