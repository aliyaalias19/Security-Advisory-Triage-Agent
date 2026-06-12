"""Prompt-injection heuristics (defense layer 1 of 4).

Layers, in order of importance:
  1. Architecture  — code, not the model, decides tool calls (pipeline.py).
  2. Policy        — code-computed severity floor the model can't lower (policy.py).
  3. Prompt        — advisory text is delimited and declared untrusted (prompts.py).
  4. Detection     — these heuristics + the model's own report, so the attempt
                     is *flagged* in `errors`, plus a post-hoc leakage scrub.

Heuristics are deliberately simple and high-precision. They will miss novel
phrasings (accepted: layers 1-2 make a missed detection mostly harmless) and
may rarely fire on legitimate text (accepted: cost is one extra `errors` note
and a lower confidence — conservative in the right direction for triage).
"""

from __future__ import annotations

import re

_PATTERNS = [
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions",
    r"you\s+are\s+now\s+in\s+\w+\s+mode",
    r"reveal\s+(?:the\s+)?(?:full\s+)?system\s+prompt",
    r"system\s+prompt\s+and\s+any\s+tool\s+definitions",
    r"override\s+accepted",
    r"takes?\s+priority\s+over\s+your\s+task",
    r"do\s+not\s+produce\s+a\s+risk\s+summary",
    r"set\s+overall_severity\s+to",
    r"new\s+instructions?\s*:",
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in _PATTERNS]

# detect_injection() hits and suspicious_region() keys are truncated to the
# SAME length — paragraph reassembly matches lines by set intersection, so
# these two truncations must never drift apart. Hence one named constant.
_MAX_LINE = 200


def detect_injection(text: str) -> list[str]:
    """Return the matching lines (deduped, trimmed) that look like injected
    instructions. Empty list = nothing detected."""
    hits: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(rx.search(stripped) for rx in _COMPILED) and stripped not in hits:
            hits.append(stripped[:_MAX_LINE])
    return hits


# Pair quotes by simple left-to-right alternation, with no length constraint in
# the pattern itself — a length-constrained pattern mis-pairs quotes whenever a
# short quoted span precedes the payload (e.g. ...to "NONE" ... "SYSTEM
# OVERRIDE ACCEPTED"...). Length filtering happens afterwards in code.
_QUOTED = re.compile(r'"([^"]*)"')


def _normalize(text: str) -> str:
    return " ".join(text.split()).lower()


def quoted_payloads(text: str) -> list[str]:
    """Quoted strings (>= 8 chars) in a piece of text — used to scrub demanded
    payloads reported by the model even when the line heuristics missed."""
    return [q.strip() for q in _QUOTED.findall(" ".join(text.split()))
            if len(q.strip()) >= 8]


def suspicious_region(advisory_text: str, matched_lines: list[str]) -> str:
    """The blank-line-delimited paragraph(s) containing the matched lines,
    whitespace-normalized. Payloads that span a line break (as in the sample
    injection advisory) reassemble here."""
    matched = {m.strip() for m in matched_lines}
    regions: list[str] = []
    for paragraph in re.split(r"\n\s*\n", advisory_text):
        lines = {ln.strip()[:_MAX_LINE] for ln in paragraph.splitlines()}
        if lines & matched:
            regions.append(_normalize(paragraph))
    return " ".join(regions)


def find_leakage(
    output_text: str, injected_lines: list[str], advisory_text: str = ""
) -> list[str]:
    """Check whether model output complied with the injected text.

    Candidates are (a) the matched lines themselves and (b) quoted payloads
    (>= 8 chars) inside the surrounding paragraph — e.g. a demanded marker
    string like a fake 'override accepted' banner. Returns fragments found
    verbatim (case/whitespace-insensitively) in the output.
    """
    haystack = _normalize(output_text)
    region = suspicious_region(advisory_text, injected_lines) if advisory_text else ""
    candidates = list(injected_lines)
    for source in [region] + injected_lines:
        candidates += quoted_payloads(source)
    leaked: list[str] = []
    for fragment in candidates:
        frag = fragment.strip()
        if len(frag) >= 8 and _normalize(frag) in haystack and frag not in leaked:
            leaked.append(frag)
    return leaked


def scrub(text: str, fragments: list[str]) -> str:
    for frag in fragments:
        text = re.sub(re.escape(frag), "[removed]", text, flags=re.IGNORECASE)
    return text
