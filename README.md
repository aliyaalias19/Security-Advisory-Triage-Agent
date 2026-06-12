# Security Advisory Triage Agent

An agent that reads a raw security advisory, extracts affected products, looks
up related CVEs with the provided `cve_lookup` tool, reasons about risk, and
emits a JSON risk summary validating against
`starter-repo/risk_summary.schema.json`.

The provided starter repo lives **unmodified** in `starter-repo/`; everything
else is mine and builds around it.

## Stack

- **Python 3.11+** (developed on 3.12), no agent framework — a deterministic
  pipeline with the LLM at exactly two points (see `DESIGN.md` for why).
- **Provider/model:** Anthropic, `claude-sonnet-4-6` by default.
- Dependencies: `anthropic`, `jsonschema`, `pytest` (pinned in
  `requirements.txt`).

## Setup & run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export ANTHROPIC_API_KEY=sk-ant-...        # required for live runs
# optional: export ANTHROPIC_MODEL=claude-sonnet-4-6

# one advisory
python triage.py starter-repo/advisories/01_clean_single_product.txt

# all five, also writing one JSON file each to results/
python triage.py --all --out results/
```

The CLI prints one schema-validated JSON object per advisory and exits
non-zero if any output fails validation (none should).

Swapping the API key is the env var above; swapping the provider entirely is
one module (`agent/llm.py`) — everything else depends only on a
`complete(system, user) -> str` interface.

## Evaluation

```bash
pytest            # 43 deterministic tests — no API key or network needed
ANTHROPIC_API_KEY=... pytest tests/test_live_advisories.py -v   # live, ~5 model-pairs of calls
```

- `tests/test_units.py` — the policy contract: severity floor, confidence
  table, injection heuristics + leakage scrubbing, tool retry/degradation.
- `tests/test_pipeline_mocked.py` — full pipeline with a scripted fake LLM and
  deterministic tool stubs. Covers all five advisory behaviours **plus** the
  combined-trap corners: the flaky tool failing *during* the malformed
  advisory, the flaky tool fully down *during* the injection advisory, a model
  that got partially fooled by the injection, hallucinated CVE ids, the LLM
  being completely unavailable, and invalid-JSON recovery via re-prompt.
- `tests/test_live_advisories.py` — the same behavioural contract against the
  real model (auto-skipped without a key). Assertions are behavioural, never
  exact-text, so they don't flake on wording. The two redis advisories may
  legitimately record `tool_failure` (~6% residual chance per lookup after 3
  retries); those tests account for it.

How I'd extend it for production: a golden dataset of real advisories with
analyst-labelled severities, regression runs on every prompt change,
LLM-as-judge scoring for rationale quality, and an adversarial corpus of
injection variants beyond the one provided.

## Notes

- The flaky `redis` lookup is handled with bounded retries (3 attempts,
  exponential backoff + jitter); on exhaustion the pipeline records
  `tool_failure: ...`, lowers confidence, and reasons from the advisory text —
  it never crashes.
- The injection advisory is processed normally, the attempt is recorded in
  `errors` as `prompt_injection_detected: ...`, demanded phrases are scrubbed
  from the output if a model ever complies, and a code-side severity floor
  makes the demanded `"NONE"` severity unreachable. Details in `DESIGN.md`.
