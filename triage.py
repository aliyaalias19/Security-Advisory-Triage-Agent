#!/usr/bin/env python3
"""CLI: run the triage agent on one or more advisory files.

Usage:
    python triage.py starter-repo/advisories/01_clean_single_product.txt
    python triage.py --all              # all five sample advisories
    python triage.py --all --out results/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent.llm import AnthropicLLM, LLMError
from agent.pipeline import triage
from agent.policy import validate_summary

ADVISORY_DIR = Path(__file__).parent / "starter-repo" / "advisories"


def main() -> int:
    parser = argparse.ArgumentParser(description="Security advisory triage agent")
    parser.add_argument("files", nargs="*", help="advisory text file(s)")
    parser.add_argument("--all", action="store_true",
                        help="run all five sample advisories")
    parser.add_argument("--out", metavar="DIR",
                        help="also write one JSON file per advisory to DIR")
    args = parser.parse_args()

    paths = [Path(f) for f in args.files]
    if args.all:
        paths += sorted(ADVISORY_DIR.glob("*.txt"))
    seen, deduped = set(), []
    for p in paths:
        key = p.resolve()
        if key not in seen:
            seen.add(key)
            deduped.append(p)
    paths = deduped
    if not paths:
        parser.error("provide advisory file(s) or --all")

    try:
        llm = AnthropicLLM()
    except LLMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    exit_code = 0
    for path in paths:
        print(f"\n===== {path.name} =====")
        try:  # the pipeline never raises by design; this guards the CLI layer
            text = path.read_text(encoding="utf-8", errors="replace")
            result = triage(text, fallback_advisory_id=path.stem, llm=llm)
        except Exception as exc:
            print(f"error: could not process {path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        problems = validate_summary(result)  # belt-and-braces final check
        if problems:
            print(f"error: {path.name} failed schema validation: {problems}",
                  file=sys.stderr)
            exit_code = 1
        print(json.dumps(result, indent=2))
        if out_dir:
            (out_dir / f"{path.stem}.json").write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
