#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a testbed-only Red Agent rollout campaign for RL reward data.")
    parser.add_argument("--target-url", default="http://localhost:8010/chat")
    parser.add_argument("--input", default="data/curated_attack_sets/testbed_meta_only.json")
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--red-model", default="")
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default="data/red_campaigns")
    parser.add_argument("--score-output", default="")
    args = parser.parse_args()

    if not (args.target_url.startswith("http://localhost") or args.target_url.startswith("http://127.0.0.1")):
        raise SystemExit("RL rollout collection is restricted to localhost/testbed targets.")

    cmd = [
        sys.executable,
        "scripts/run_red_adaptive_campaign.py",
        "--target-url",
        args.target_url,
        "--input",
        args.input,
        "--seeds",
        str(args.seeds),
        "--rounds",
        str(args.rounds),
        "--seed",
        str(args.seed),
        "--conversation-mode",
        "multi",
        "--verify-tool-execution",
        "--campaign-id",
        args.campaign_id,
        "--output-dir",
        args.output_dir,
    ]
    if args.red_model:
        cmd.extend(["--red-model", args.red_model])

    subprocess.run(cmd, cwd=ROOT, check=True)
    raw_path = ROOT / args.output_dir / "raw" / f"{args.campaign_id}_raw.json"
    if not raw_path.exists():
        raise SystemExit(f"raw campaign output not found: {raw_path}")

    score_output = args.score_output or f"data/rl_red_agent/scored/{args.campaign_id}_scored.jsonl"
    dpo_output = f"data/rl_red_agent/preferences/{args.campaign_id}_dpo_pairs.jsonl"
    subprocess.run(
        [
            sys.executable,
            "scripts/rl_build_red_preference_dataset.py",
            "--input",
            str(raw_path),
            "--scored-output",
            score_output,
            "--dpo-output",
            dpo_output,
        ],
        cwd=ROOT,
        check=True,
    )
    print(json.dumps({"raw": str(raw_path), "scored": score_output, "dpo": dpo_output}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

