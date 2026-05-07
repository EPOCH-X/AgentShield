#!/usr/bin/env python3
"""Run the existing adaptive Red Agent campaign for the dashboard demo.

This wrapper does not duplicate Red Agent logic. It creates a one-seed input
file from the demo prompt, invokes scripts/run_red_adaptive_campaign.py, then
returns a compact JSON summary for the frontend.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN_SCRIPT = PROJECT_ROOT / "scripts" / "run_red_adaptive_campaign.py"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run demo Red Agent adaptive rounds.")
    parser.add_argument("--target-url", default=os.getenv("TESTBED_CHAT_URL", "http://127.0.0.1:8010/chat"))
    parser.add_argument("--red-model", default=os.getenv("RED_CAMPAIGN_MODEL") or os.getenv("OLLAMA_RED_MODEL"))
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=57)
    parser.add_argument("--category", default="LLM02")
    parser.add_argument("--subcategory", default="config-extraction")
    parser.add_argument("--initial-prompt", default="")
    parser.add_argument("--initial-prompt-stdin", action="store_true")
    parser.add_argument("--timeout", type=int, default=600)
    return parser.parse_args()


def read_prompt(args: argparse.Namespace) -> str:
    if args.initial_prompt_stdin:
        return sys.stdin.read().strip()
    return str(args.initial_prompt or "").strip()


def write_seed_file(prompt: str, args: argparse.Namespace) -> Path:
    payload = [
        {
            "id": f"demo-seed-{uuid.uuid4().hex[:8]}",
            "seed_id": "demo-ui-seed",
            "category": args.category,
            "subcategory": args.subcategory,
            "attack_prompt": prompt,
            "target_response": "",
            "detail": "Dashboard demo seed prompt",
        }
    ]
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".json",
        prefix="agentshield-demo-red-",
        delete=False,
    )
    with tmp:
        json.dump(payload, tmp, ensure_ascii=False, indent=2)
    return Path(tmp.name)


def find_raw_path(output: str) -> Path | None:
    match = re.search(r"\[INFO\]\s+raw campaign saved:\s+(.+?\.json)", output)
    if match:
        path = Path(match.group(1).strip())
        if path.exists():
            return path

    raw_dir = PROJECT_ROOT / "data" / "red_campaigns" / "raw"
    candidates = sorted(raw_dir.glob("*_raw.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def summarize_campaign(raw_path: Path | None, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ok": returncode == 0,
        "returncode": returncode,
        "raw_path": str(raw_path) if raw_path else None,
        "rounds": [],
        "best_round": None,
        "success": False,
        "stderr_tail": stderr[-4000:],
        "stdout_tail": stdout[-4000:],
    }
    if not raw_path or not raw_path.exists():
        return result

    with raw_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    items = data.get("items") or []
    if not items:
        return result

    item = items[0]
    result["success"] = bool(item.get("success"))
    result["best_round"] = item.get("best_round")
    result["campaign_id"] = data.get("campaign_id")
    result["red_model"] = data.get("red_model")
    result["target_url"] = data.get("target_url")

    rounds: list[dict[str, Any]] = []
    for entry in item.get("rounds") or []:
        attack_prompt = str(entry.get("mutated_prompt") or entry.get("attack_prompt") or "")
        target_response = str(entry.get("target_response") or "")
        rounds.append(
            {
                "round": entry.get("round"),
                "category": entry.get("category"),
                "subcategory": entry.get("subcategory"),
                "attack_prompt": attack_prompt,
                "target_response": target_response,
                "judgment": entry.get("judgment"),
                "confidence": entry.get("judgment_confidence"),
                "success": bool(entry.get("success")),
                "success_strength": entry.get("success_strength"),
                "exploit_type": entry.get("exploit_type"),
                "detail": entry.get("detail"),
                "attack_len": len(attack_prompt),
                "response_len": len(target_response),
                "generation_failed": entry.get("judgment") == "generation_failed",
            }
        )
    result["rounds"] = rounds
    return result


def main() -> int:
    args = parse_args()
    prompt = read_prompt(args)
    if not prompt:
        print(json.dumps({"ok": False, "detail": "initial prompt is empty"}, ensure_ascii=False))
        return 2

    seed_path = write_seed_file(prompt, args)
    campaign_id = f"demo-red-{uuid.uuid4().hex[:10]}"

    cmd = [
        sys.executable,
        str(CAMPAIGN_SCRIPT),
        "--target-url",
        args.target_url,
        "--input",
        str(seed_path),
        "--seeds",
        "1",
        "--rounds",
        str(args.rounds),
        "--seed",
        str(args.seed),
        "--category",
        args.category,
        "--campaign-id",
        campaign_id,
        "--conversation-mode",
        "multi",
        "--verify-tool-execution",
    ]
    if args.red_model:
        cmd.extend(["--red-model", str(args.red_model)])

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            text=True,
            capture_output=True,
            timeout=args.timeout,
            check=False,
        )
        combined_output = f"{proc.stdout}\n{proc.stderr}"
        raw_path = find_raw_path(combined_output)
        payload = summarize_campaign(raw_path, proc.stdout, proc.stderr, proc.returncode)
        print(json.dumps(payload, ensure_ascii=False))
        return 0 if proc.returncode == 0 else proc.returncode
    except subprocess.TimeoutExpired as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "detail": "red adaptive campaign timeout",
                    "timeout": args.timeout,
                    "stdout_tail": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
                    "stderr_tail": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
                },
                ensure_ascii=False,
            )
        )
        return 124
    finally:
        try:
            seed_path.unlink(missing_ok=True)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
