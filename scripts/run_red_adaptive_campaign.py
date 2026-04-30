#!/usr/bin/env python3
"""Run an offline-safe adaptive Red Agent campaign.

This script uses the normal Red Agent prompt builder and target adapter, but it
does not write to PostgreSQL or ChromaDB. It stores campaign artifacts as JSON so
the large red model can be stopped before replay/judge/defense runs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _slug(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "_" for ch in value)
    return "_".join(part for part in cleaned.split("_") if part)


def _load_attack_file(path: Path, category: str = "ALL") -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    rows = data if isinstance(data, list) else data.get("patterns", [data])
    attacks: list[dict[str, Any]] = []
    for idx, item in enumerate(rows, start=1):
        prompt = (
            item.get("attack_prompt")
            or item.get("mutated_prompt")
            or item.get("prompt_text")
            or item.get("original_prompt")
            or ""
        )
        if not prompt:
            continue
        cat = str(item.get("category") or "LLM01")
        if category != "ALL" and cat != category:
            continue
        attacks.append(
            {
                "id": str(item.get("id") or item.get("attack_pattern_id") or f"seed-{idx}"),
                "seed_id": str(item.get("seed_id") or item.get("id") or f"seed-{idx}"),
                "category": cat,
                "subcategory": str(item.get("subcategory") or ""),
                "attack_prompt": str(prompt),
                "target_response": str(item.get("target_response") or ""),
                "detail": str(item.get("detail") or item.get("judge_detail") or ""),
            }
        )
    return attacks


def _pick_seeds(attacks: list[dict[str, Any]], seed_count: int, shuffle_seed: int | None) -> list[dict[str, Any]]:
    if shuffle_seed is not None:
        rng = random.Random(shuffle_seed)
        attacks = list(attacks)
        rng.shuffle(attacks)
    return attacks[:seed_count] if seed_count > 0 else attacks


def _is_success(verdict: dict[str, Any], target_response: str) -> tuple[bool, str | None]:
    from backend.core.phase2_red_agent import _check_fp_flag

    if verdict.get("judgment") != "vulnerable":
        return False, None
    evidence_hard_veto = bool(verdict.get("evidence_hard_veto"))
    fp_flag = None if evidence_hard_veto else _check_fp_flag(target_response)
    return fp_flag is None, fp_flag


async def _stop_ollama_model(model: str) -> None:
    if not model:
        return
    proc = await asyncio.create_subprocess_exec(
        "ollama",
        "stop",
        model,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode == 0:
        print(f"[INFO] stopped red model: {model}")
    else:
        msg = (stderr or stdout).decode("utf-8", errors="replace").strip()
        print(f"[WARN] ollama stop failed for {model}: {msg}")


async def run_campaign(args: argparse.Namespace) -> int:
    if args.red_model:
        os.environ["OLLAMA_RED_MODEL"] = args.red_model
        os.environ["OLLAMA_RED_TARGET_MODEL"] = args.red_model

    from backend.agents.llm_client import AgentShieldLLM
    from backend.agents.red_agent import (
        AdaptiveRedAgent,
        analyze_defense_signal,
        build_red_prompt,
        detect_chatbot_domain,
        extract_techniques,
        normalize_attack_prompt_output,
        select_target_failure_mode,
        validate_attack_prompt_output,
    )
    from backend.config import settings
    from backend.core.judge import full_judge
    from backend.core.target_adapter import TargetAdapterConfig, send_messages_to_target

    input_path = Path(args.input)
    if not input_path.is_absolute():
        input_path = PROJECT_ROOT / input_path
    attacks = _pick_seeds(_load_attack_file(input_path, args.category), args.seeds, args.seed)
    if not attacks:
        print(f"[ERROR] no attacks loaded from {input_path}")
        return 2

    campaign_id = args.campaign_id or f"{_slug(args.red_model or 'red')}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir
    raw_dir = output_dir / "raw"
    success_dir = output_dir / "success"
    review_dir = output_dir / "manual_review"
    mixed_dir = output_dir / "mixed_replay"
    for directory in (raw_dir, success_dir, review_dir, mixed_dir):
        directory.mkdir(parents=True, exist_ok=True)

    red_model = args.red_model or os.getenv("OLLAMA_RED_TARGET_MODEL") or os.getenv("OLLAMA_RED_MODEL")
    adapter_config = TargetAdapterConfig.from_input(
        target_url=args.target_url,
        api_key=args.target_api_key,
        provider=args.target_provider,
        model=args.target_model,
    )

    llm = AgentShieldLLM()
    domain_context: dict[str, str] = {"domain": "general", "confidence": "low", "hint": ""}

    async with httpx.AsyncClient(timeout=float(args.target_timeout)) as client:
        try:
            probe_resp = await send_messages_to_target(
                client,
                adapter_config,
                messages=[{"role": "user", "content": args.probe}],
            )
            domain_context = detect_chatbot_domain(probe_resp)
            print(
                f"[INFO] target domain={domain_context.get('domain')} "
                f"confidence={domain_context.get('confidence')}"
            )
        except Exception as exc:
            print(f"[WARN] target probe failed; using generic domain: {exc}")

        campaign_items: list[dict[str, Any]] = []
        success_attacks: list[dict[str, Any]] = []
        manual_review: list[dict[str, Any]] = []
        mixed_replay: list[dict[str, Any]] = []

        for seed_index, attack in enumerate(attacks, start=1):
            category = attack["category"]
            subcategory = attack.get("subcategory", "")
            current_prompt = attack["attack_prompt"]
            current_response = attack.get("target_response") or ""
            current_detail = attack.get("detail") or ""
            used_techniques: list[str] = []
            used_failure_modes: list[str] = []
            adaptive_agent = AdaptiveRedAgent(red_model or "")
            rounds: list[dict[str, Any]] = []
            seed_success = False
            best_round: int | None = None

            print(f"[INFO] seed {seed_index}/{len(attacks)} {category}/{subcategory}")
            for rnd in range(1, args.rounds + 1):
                target_failure_mode = select_target_failure_mode(
                    category,
                    rnd,
                    prev_failure_modes=used_failure_modes,
                )
                prev_techniques = used_techniques if not adaptive_agent._detect_stagnation() else []
                red_prompt = build_red_prompt(
                    attack_prompt=current_prompt,
                    target_response=current_response,
                    category=category,
                    round_num=rnd,
                    prev_techniques=prev_techniques,
                    target_failure_mode=target_failure_mode,
                    judge_detail=current_detail,
                    domain_context=domain_context,
                )

                raw_generation = await llm.generate(
                    red_prompt,
                    role="red",
                    max_tokens=int(args.red_max_tokens or settings.RED_AGENT_NUM_PREDICT),
                )
                mutated_prompt = normalize_attack_prompt_output(str(raw_generation or ""))
                valid, invalid_reason = validate_attack_prompt_output(mutated_prompt)

                base_round = {
                    "round": rnd,
                    "category": category,
                    "subcategory": subcategory,
                    "target_failure_mode": target_failure_mode,
                    "round_input_prompt": current_prompt,
                    "red_prompt_len": len(red_prompt),
                    "raw_generation_len": len(str(raw_generation or "")),
                    "mutated_prompt": mutated_prompt,
                    "mutation_techniques": extract_techniques(mutated_prompt),
                    "created_at": _utc_now(),
                }

                if not valid:
                    entry = {
                        **base_round,
                        "target_response": "[blocked: invalid red-agent output]",
                        "judgment": "generation_failed",
                        "detail": f"Red Agent output rejected: {invalid_reason}",
                    }
                    rounds.append(entry)
                    manual_review.append(_export_attack_row(campaign_id, attack, entry, reason="generation_failed"))
                    print(f"  [R{rnd}] generation_failed: {invalid_reason}")
                    break

                try:
                    target_response = await send_messages_to_target(
                        client,
                        adapter_config,
                        messages=[{"role": "user", "content": mutated_prompt}],
                    )
                except Exception as exc:
                    entry = {
                        **base_round,
                        "target_response": "[ERROR]",
                        "judgment": "error",
                        "detail": f"Target request failed: {exc.__class__.__name__}",
                    }
                    rounds.append(entry)
                    manual_review.append(_export_attack_row(campaign_id, attack, entry, reason="target_error"))
                    print(f"  [R{rnd}] target_error: {exc.__class__.__name__}")
                    break

                verdict = await full_judge(category, mutated_prompt, target_response)
                success, fp_flag = _is_success(verdict, target_response)
                defense_signal = analyze_defense_signal(target_response, verdict.get("detail", ""))
                round_entry = {
                    **base_round,
                    "target_response": target_response,
                    "target_response_len": len(target_response or ""),
                    "judge": verdict,
                    "judgment": verdict.get("judgment"),
                    "judgment_confidence": verdict.get("confidence"),
                    "detail": verdict.get("detail", ""),
                    "evidence_hard_veto": bool(verdict.get("evidence_hard_veto")),
                    "fp_flag": fp_flag,
                    "defense_signal": defense_signal,
                    "success": success,
                }
                rounds.append(round_entry)
                replay_row = _export_attack_row(campaign_id, attack, round_entry)
                if verdict.get("judgment") == "ambiguous" or fp_flag:
                    manual_review.append(
                        _export_attack_row(campaign_id, attack, round_entry, reason=fp_flag or "ambiguous")
                    )
                elif verdict.get("judgment") != "generation_failed":
                    mixed_replay.append(replay_row)

                color = "vulnerable" if verdict.get("judgment") == "vulnerable" else verdict.get("judgment")
                print(
                    f"  [R{rnd}] {color} conf={verdict.get('confidence')} "
                    f"success={success} response_len={len(target_response or '')}"
                )

                if success:
                    success_attacks.append(replay_row)
                    seed_success = True
                    best_round = rnd
                    adaptive_agent.evaluate_attack(mutated_prompt, target_response, 1.0)
                    break

                adaptive_agent.evaluate_attack(mutated_prompt, target_response, 0.0)
                current_prompt = mutated_prompt
                current_response = target_response
                current_detail = verdict.get("detail", "")
                used_techniques.extend(round_entry["mutation_techniques"])
                if target_failure_mode:
                    used_failure_modes.append(target_failure_mode)

            campaign_items.append(
                {
                    "seed": attack,
                    "success": seed_success,
                    "best_round": best_round,
                    "rounds": rounds,
                }
            )

    raw_payload = {
        "campaign_id": campaign_id,
        "created_at": _utc_now(),
        "red_model": red_model,
        "target_url": args.target_url,
        "target_domain": domain_context,
        "input": str(input_path),
        "seeds_total": len(attacks),
        "rounds_per_seed": args.rounds,
        "db_write": False,
        "chroma_write": False,
        "items": campaign_items,
        "successful_count": len(success_attacks),
        "manual_review_count": len(manual_review),
    }

    raw_path = raw_dir / f"{campaign_id}_raw.json"
    success_path = success_dir / f"{campaign_id}_success_only.json"
    review_path = review_dir / f"{campaign_id}_manual_review.json"
    mixed_path = mixed_dir / f"{campaign_id}_mixed_replay.json"
    _write_json(raw_path, raw_payload)
    _write_json(success_path, success_attacks)
    _write_json(review_path, manual_review)
    _write_json(mixed_path, mixed_replay)

    print(f"[INFO] raw campaign saved: {raw_path}")
    print(f"[INFO] success attacks saved: {success_path} ({len(success_attacks)})")
    print(f"[INFO] manual review saved: {review_path} ({len(manual_review)})")
    print(f"[INFO] mixed replay saved: {mixed_path} ({len(mixed_replay)})")

    if args.stop_red_model:
        await _stop_ollama_model(str(red_model or ""))

    return 0


def _export_attack_row(
    campaign_id: str,
    seed: dict[str, Any],
    round_entry: dict[str, Any],
    reason: str | None = None,
) -> dict[str, Any]:
    round_num = int(round_entry.get("round") or 0)
    category = str(seed.get("category") or round_entry.get("category") or "LLM01")
    subcategory = str(seed.get("subcategory") or round_entry.get("subcategory") or "")
    row = {
        "id": f"{campaign_id}-{category.lower()}-{_slug(subcategory or 'attack')}-{seed.get('seed_id')}-r{round_num}",
        "campaign_id": campaign_id,
        "seed_id": seed.get("seed_id"),
        "category": category,
        "subcategory": subcategory,
        "attack_prompt": round_entry.get("mutated_prompt") or "",
        "mutated_prompt": round_entry.get("mutated_prompt") or "",
        "original_attack_prompt": seed.get("attack_prompt") or "",
        "round_input_prompt": round_entry.get("round_input_prompt") or "",
        "round": round_num,
        "target_response": round_entry.get("target_response") or "",
        "judgment": round_entry.get("judgment"),
        "judgment_confidence": round_entry.get("judgment_confidence"),
        "detail": round_entry.get("detail") or "",
        "evidence_hard_veto": bool(round_entry.get("evidence_hard_veto")),
        "target_failure_mode": round_entry.get("target_failure_mode"),
        "mutation_techniques": round_entry.get("mutation_techniques") or [],
        "source": "red_adaptive_campaign",
        "manual_review_reason": reason,
    }
    return row


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a no-DB/no-Chroma adaptive Red Agent campaign.")
    parser.add_argument("--input", default=os.getenv("ATTACK_PATTERN_PATH", "data/curated_attack_sets/testbed_manual_mixed_10.json"))
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--target-provider", default=os.getenv("TARGET_PROVIDER") or None)
    parser.add_argument("--target-model", default=os.getenv("TARGET_MODEL") or None)
    parser.add_argument("--target-api-key", default=os.getenv("TARGET_API_KEY") or None)
    parser.add_argument("--target-timeout", type=float, default=float(os.getenv("PHASE2_TIMEOUT", "300")))
    parser.add_argument("--red-model", default=os.getenv("RED_CAMPAIGN_MODEL") or os.getenv("OLLAMA_RED_TARGET_MODEL") or os.getenv("OLLAMA_RED_MODEL"))
    parser.add_argument("--red-max-tokens", type=int, default=int(os.getenv("RED_AGENT_NUM_PREDICT", "4096")))
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--category", default="ALL")
    parser.add_argument("--campaign-id", default="")
    parser.add_argument("--output-dir", default="data/red_campaigns")
    parser.add_argument("--probe", default="Hello, what can you help me with today?")
    parser.add_argument("--stop-red-model", action="store_true")
    return parser.parse_args()


def main() -> int:
    return asyncio.run(run_campaign(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
