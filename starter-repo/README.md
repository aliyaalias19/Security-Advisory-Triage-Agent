# Security Advisory Triage — Starter Repo

This is the starting point for the take-home. It gives you a mock tool, an
output schema, and sample inputs so you can focus on building the **agent**, not
boilerplate.

## What's here

```
starter-repo/
├── cve_lookup.py              # Mock "tool": lookup_cves(product, version) -> [CVERecord]
├── risk_summary.schema.json   # The structured output your agent must produce
├── advisories/                # Sample inputs (read these before you start)
│   ├── 01_clean_single_product.txt
│   ├── 02_multi_product.txt
│   ├── 03_malformed_incomplete.txt
│   ├── 04_prompt_injection.txt
│   └── 05_unknown_product.txt
└── requirements.txt
```

## The tool

`cve_lookup.lookup_cves(product, version=None)` returns a list of CVE records.
Treat it as the external capability you expose to your agent. Things to know:

- Matching is by product name (case-insensitive). Version reasoning is left to you.
- Some products return multiple CVEs, some return none.
- **`redis` is intentionally flaky** — `lookup_cves("redis")` raises
  `CVELookupError` roughly 40% of the time to simulate a transient API failure.
  Your agent must handle this, not crash.

```python
from cve_lookup import lookup_cves, CVELookupError

try:
    hits = lookup_cves("OpenSSL", "3.0.5")
except CVELookupError:
    ...  # your call: retry? degrade? record an error?
```

## The output

Your agent's final result for each advisory must be a JSON object that validates
against `risk_summary.schema.json`. Don't return free-form prose as the result.

## The inputs

The five advisories cover a clean case, a multi-product case, a malformed/
incomplete message, an unknown product (empty lookup), and one with a planted
**prompt-injection** string. Your agent should handle all of them sensibly — see
the brief for what "sensibly" means.

## Ground rules

- Use **any language, framework, and model** you like. There is no required stack.
- AI coding assistants are allowed and encouraged. You will be asked to explain
  and modify your code live, so understand everything you submit.
- Don't modify `cve_lookup.py` or the schema — build around them. (You may add
  files freely.)

See `takehome_brief.md` for the full task, deliverables, and time box.
