#!/usr/bin/env python3
"""Filter Red SFT messages JSONL into a strict clean training set."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.agents.red_sft_seed_agent import validate_sft_seed_output


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else PROJECT_ROOT / p


def _assistant_text(row: dict[str, Any]) -> str:
    messages = row.get("messages") or []
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            return str(msg.get("content") or "")
    return ""


def _dedup_key(text: str) -> str:
    return " ".join(text.lower().split())[:800]


def main() -> int:
    parser = argparse.ArgumentParser(description="Strictly filter Red Agent SFT messages JSONL.")
    parser.add_argument("--input", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--rejected-output", default="")
    parser.add_argument("--report-output", default="")
    parser.add_argument("--min-chars", type=int, default=500)
    parser.add_argument("--max-chars", type=int, default=10000)
    args = parser.parse_args()

    output = _resolve(args.output)
    rejected_output = _resolve(args.rejected_output) if args.rejected_output else output.with_suffix(".rejected.json")
    report_output = _resolve(args.report_output) if args.report_output else output.with_suffix(".report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    rejected_output.parent.mkdir(parents=True, exist_ok=True)
    report_output.parent.mkdir(parents=True, exist_ok=True)

    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    reasons: Counter[str] = Counter()
    seen: set[str] = set()
    total = 0

    for raw_path in args.input:
        path = _resolve(raw_path)
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            total += 1
            row = json.loads(line)
            prompt = _assistant_text(row)
            ok, reason, evidence = validate_sft_seed_output(
                prompt,
                min_chars=args.min_chars,
                max_chars=args.max_chars,
                carrier="default",
            )
            key = _dedup_key(prompt)
            if ok and key in seen:
                ok, reason, evidence = False, "duplicate attack prompt", ""
            if ok:
                seen.add(key)
                accepted.append(row)
                continue
            reasons[reason] += 1
            rejected.append(
                {
                    "input": str(path),
                    "line": line_no,
                    "reason": reason,
                    "evidence": evidence[:240],
                    "assistant_head": prompt[:500],
                }
            )

    with output.open("w", encoding="utf-8") as fh:
        for row in accepted:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    rejected_output.write_text(json.dumps(rejected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = {
        "inputs": args.input,
        "output": str(output),
        "rejected_output": str(rejected_output),
        "total": total,
        "accepted": len(accepted),
        "rejected": len(rejected),
        "rejection_reasons": dict(reasons.most_common()),
    }
    report_output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
