#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.rl.red_reward_evaluator import RedRewardEvaluator
from backend.rl.red_reward_policy import DEFAULT_MAX_REJECT_SCORE, DEFAULT_MIN_TRAINING_SCORE
from backend.rl.red_reward_types import RedRewardInput
from backend.rl.red_rollout_recorder import build_preference_pairs, flatten_campaign_raw, read_jsonl, write_jsonl


def _load_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".jsonl":
        return read_jsonl(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "items" in data:
        return flatten_campaign_raw(data)
    if isinstance(data, list):
        return data
    raise ValueError(f"Unsupported rollout format: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Score Red Agent rollouts and build DPO preference pairs.")
    parser.add_argument("--input", required=True, help="raw campaign .json or rollout .jsonl")
    parser.add_argument("--scored-output", default=str(Path(tempfile.gettempdir()) / "agentshield-rl-red-agent" / "scored" / "red_rollouts_scored.jsonl"))
    parser.add_argument("--dpo-output", default=str(Path(tempfile.gettempdir()) / "agentshield-rl-red-agent" / "preferences" / "red_dpo_pairs.jsonl"))
    parser.add_argument("--chosen-min", type=float, default=float(os.getenv("RL_RED_REWARD_MIN_CHOSEN", DEFAULT_MIN_TRAINING_SCORE)))
    parser.add_argument("--rejected-max", type=float, default=float(os.getenv("RL_RED_REWARD_MAX_REJECTED", DEFAULT_MAX_REJECT_SCORE)))
    args = parser.parse_args()

    evaluator = RedRewardEvaluator()
    rows = _load_rows(Path(args.input))
    scored: list[dict[str, Any]] = []
    for row in rows:
        result = evaluator.evaluate(
            RedRewardInput(
                attack_prompt=str(row.get("attack_prompt") or row.get("mutated_prompt") or ""),
                target_response=str(row.get("target_response") or ""),
                category=str(row.get("category") or "LLM01"),
                round=int(row.get("round") or 0),
                seed_id=str(row.get("seed_id") or row.get("id") or ""),
                judge=dict(row.get("judge") or {}),
                tool_trace=list(row.get("tool_trace") or []),
                metadata=row,
            )
        )
        enriched = dict(row)
        enriched.update(
            {
                "reward_score": result.score,
                "reward_raw_score": result.raw_score,
                "reward_positives": result.positives,
                "reward_negatives": result.negatives,
                "training_eligible": result.training_eligible,
                "reward_exploit_value": result.exploit_value,
            }
        )
        scored.append(enriched)

    pairs = build_preference_pairs(scored, chosen_min=args.chosen_min, rejected_max=args.rejected_max)
    scored_count = write_jsonl(args.scored_output, scored)
    pair_count = write_jsonl(args.dpo_output, pairs)
    print(json.dumps({"scored": scored_count, "pairs": pair_count, "scored_output": args.scored_output, "dpo_output": args.dpo_output}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
