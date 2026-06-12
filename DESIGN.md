# Design

**Thesis: the agent's autonomy is constrained to exactly the decisions that
need intelligence; everything else is deterministic, testable code.**

## Architecture & why

A fixed pipeline — *extract → look up → assess → policy → validate*
(`agent/pipeline.py`) — with the LLM invoked at exactly two points:

1. **Extraction** (`prompts.EXTRACTION_SYSTEM`): advisory text → products,
   versions, advisory id, malformed-ness. Tuned for recall (a wasted lookup is
   cheap; a missed product is not).
2. **Assessment** (`prompts.ASSESSMENT_SYSTEM`): advisory + sanitized tool
   results → CVE relevance per product, severity, action, rationale.

I deliberately did **not** use a ReAct-style loop or an agent framework. The
task has a fixed shape, and a free-roaming loop makes the three hard cases
worse: it's non-deterministic (untestable assertions), it lets injected text
influence tool-calling, and it fails unpredictably on malformed input. "Agentic"
here means the model makes the *judgment calls* (what's affected, which CVEs
are version-relevant, how bad it is) — code makes the *mechanical* ones (when
to call the tool, with what arguments, what's allowed in the output). With more
structure needed (branching, human-in-the-loop), I'd reach for LangGraph; for a
4-step linear flow it adds concepts without payoff.

The LLM proposes; the policy layer (`agent/policy.py`, pure functions)
disposes:

- **Severity floor** — code computes the max severity of the *relevant* CVEs
  from the tool's own records (keyed by CVE id, so values can't be spoofed).
  The model may raise severity with justification; it can never go below the
  floor (`severity_conflict` is recorded if it tries).
- **Confidence** — computed from observed degradations (0 → 0.9, one → 0.6,
  malformed/compounding → 0.3); the model's suggestion is clamped to that
  ceiling, never trusted upward.
- **Anti-hallucination** — claimed CVE ids are intersected with what the tool
  actually returned; inventions are dropped and recorded.

## Failure handling

Every failure degrades into the `errors` array (machine-checkable
`code: detail` strings) plus a lower confidence; the pipeline always returns a
schema-valid object. One mechanism covers all the failure advisories: flaky
tool (bounded retries ×3, exponential backoff + jitter, then degrade),
malformed input (model flags it, recall-first extraction keeps what it can),
unknown product (empty lookup → reason from text with a conservative rubric:
unclear impact defaults to MEDIUM, never low). Even a fully unavailable LLM
yields a valid "route to a human" summary. Final output is validated against
the **provided** schema file; model JSON is re-prompted with the concrete
validation errors (≤3 attempts) before degrading.

## The injection (advisory 04)

Advisory text is untrusted data, enforced in four layers: **(1) architecture** —
code, not the model, issues tool calls, so injected text can't redirect tools;
**(2) policy** — the severity floor makes the demanded `"NONE"` unreachable
when CVE evidence exists, and a detected injection floors severity at MEDIUM
even when the tool is down (an advisory carrying an active manipulation attempt
is never no-risk) — this rule is what holds in the worst corner, injection +
total tool outage, which has its own test; **(3) prompts** — delimited input
declared untrusted in both calls, tool results included (in production CVE
descriptions are third-party text — the same second injection surface, so they
get the same sanitization and framing); **(4) detection & scrubbing** —
pre-LLM heuristics plus the model's own report put the attempt in `errors`,
and a post-hoc check scrubs demanded phrases (handling payloads split across
line breaks, a real bug the sample advisory exposed) if a model ever complies.
A fooled model is therefore detected, contained, and visible — not just
hopefully absent.

## How I know it works

43 deterministic tests run with no key: unit tests pin the policy contract;
pipeline tests with a scripted fake LLM cover all five advisories *plus* the
corners the brief implies but doesn't state (tool outage during the injection
advisory; a partially-fooled model; hallucinated CVEs; invalid JSON recovery).
A live suite asserts the same behavioural contract against the real model —
behavioural bounds, never exact text, with the residual ~6% redis-failure
chance accounted for. Production extension: golden analyst-labelled dataset,
prompt-change regression runs, LLM-as-judge for rationale quality, adversarial
injection corpus.

A post-build adversarial review pass found two real defects this suite had
missed — a sanitizer turning `fixed_in: None` into the string `"None"`, and
(worse, a safety-direction bug) severity collapsing to NONE when the assessment
stage failed, because the floor was derived only from *model-selected* CVEs.
Both are fixed with named regression tests; the failure floor now falls back to
all returned CVE evidence and never below MEDIUM. The review is part of the
evaluation story: behavioural tests bound outcomes, review catches wrong
assumptions. The same cycle also added loose product-name reconciliation
(unambiguous prefix only, anything else recorded as product_name_mismatch)
and unified the leak-scrub trigger: it fires on heuristic detection OR the
model's own injection report, so a regex-evading attempt still gets scrubbed.

## Trade-offs owned / with more time

- **No self-correction:** if extraction misses a product, nothing downstream
  recovers it. Mitigated by recall-first prompting; accepted for determinism.
- **Version relevance is judged by the model, not parsed:** ranges like
  "1.1.1 – 1.1.1t" make a naive parser a bug farm. Code verifies *which* CVEs
  exist; the model judges *applicability* and must explain it. With more time:
  a proper version-range library as a cross-check.
- **Max-severity aggregation over-alerts** (one critical dominates ten lows) —
  the right asymmetry for triage; per-product detail remains in the output.
- **Heuristic detection misses novel phrasings** — accepted because layers 1–2
  make an undetected injection mostly harmless; production answer is a guard
  model. With more time I'd also add structured logging/tracing per stage
  (token usage, per-stage latency, tool-failure rates), parallel lookups for
  multi-product advisories, and a real vulnerability source (NVD API) behind
  the same retry/sanitize wrapper.
