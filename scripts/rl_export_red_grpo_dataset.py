#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.rl.red_rollout_recorder import read_jsonl, write_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description="Export scored Red Agent rollouts into a GRPO prompt dataset.")
    parser.add_argument("--scored-input", required=True)
    parser.add_argument("--output", default=str(Path(tempfile.gettempdir()) / "agentshield-rl-red-agent" / "grpo" / "red_grpo_prompts.jsonl"))
    parser.add_argument("--min-score", type=float, default=0.35)
    args = parser.parse_args()

    rows = read_jsonl(args.scored_input)
    out = []
    for row in rows:
        if float(row.get("reward_score", 0.0)) < args.min_score:
            continue
        prompt = row.get("red_prompt") or row.get("round_input_prompt") or row.get("original_attack_prompt") or ""
        if not prompt:
            continue
        out.append(
            {
                "prompt": prompt,
                "category": row.get("category", ""),
                "round": row.get("round", 0),
                "seed_id": row.get("seed_id", ""),
                "reference_reward": row.get("reward_score", 0.0),
            }
        )
    count = write_jsonl(args.output, out)
    print(json.dumps({"count": count, "output": args.output}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
