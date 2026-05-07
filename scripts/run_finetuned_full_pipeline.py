#!/usr/bin/env python3
"""
Fine-tuned AgentShield integrated pipeline runner for the local testbed.

This runs the real multi-agent graph:
  Phase1 scan -> Phase2 red mutation -> Judge -> Phase3 Blue defense
  -> Phase4 Judge recheck -> DB/Chroma artifacts -> review logs.

Target is intentionally the local testbed URL. This avoids hitting external
production chatbots while still exercising the real integration surface.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")

from backend.graph.llm_security_graph import run_scan  # noqa: E402
from backend.core.target_adapter import TargetAdapterConfig  # noqa: E402
from scripts.run_phase1_to_4_smoke import (  # noqa: E402
    _ensure_test_session,
    _log_ts,
    _make_phase1_result_printer,
    _patched_llm_runtime,
    _patched_phase1_loader,
    _patched_phase2_rounds,
    _short_summary,
    _write_review_log,
)


def _apply_env_model_routing(args: argparse.Namespace) -> dict[str, str]:
    """Apply .env runtime model names before AgentShield clients are instantiated."""
    model_map = {
        "red": os.getenv("OLLAMA_RED_MODEL", ""),
        "judge": os.getenv("OLLAMA_JUDGE_MODEL", "agent_judge:latest"),
        "blue": os.getenv("OLLAMA_BLUE_MODEL", ""),
        "target": os.getenv("OLLAMA_MODEL", ""),
        "ollama_base_url": args.ollama_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
    }

    if model_map["red"]:
        os.environ["OLLAMA_RED_MODEL"] = model_map["red"]
        os.environ["OLLAMA_RED_TARGET_MODEL"] = model_map["red"]
    if model_map["judge"]:
        os.environ["OLLAMA_JUDGE_MODEL"] = model_map["judge"]
        os.environ["OLLAMA_JUDGE_TARGET_MODEL"] = model_map["judge"]
        os.environ["OLLAMA_GUARD_MODEL"] = model_map["judge"]
    if model_map["blue"]:
        os.environ["OLLAMA_BLUE_MODEL"] = model_map["blue"]
        os.environ["OLLAMA_BLUE_TARGET_MODEL"] = model_map["blue"]
    if model_map["target"]:
        os.environ["OLLAMA_MODEL"] = model_map["target"]
        os.environ["OLLAMA_BASE_TARGET_MODEL"] = os.getenv("OLLAMA_BASE_TARGET_MODEL", model_map["target"])
    if model_map["ollama_base_url"]:
        os.environ["OLLAMA_BASE_URL"] = model_map["ollama_base_url"]

    from backend.config import settings

    settings.OLLAMA_RED_MODEL = os.environ.get("OLLAMA_RED_MODEL", settings.OLLAMA_RED_MODEL)
    settings.OLLAMA_RED_TARGET_MODEL = os.environ.get("OLLAMA_RED_TARGET_MODEL", settings.OLLAMA_RED_TARGET_MODEL)
    settings.OLLAMA_JUDGE_MODEL = os.environ.get("OLLAMA_JUDGE_MODEL", settings.OLLAMA_JUDGE_MODEL)
    settings.OLLAMA_JUDGE_TARGET_MODEL = os.environ.get("OLLAMA_JUDGE_TARGET_MODEL", settings.OLLAMA_JUDGE_TARGET_MODEL)
    settings.OLLAMA_GUARD_MODEL = os.environ.get("OLLAMA_GUARD_MODEL", settings.OLLAMA_GUARD_MODEL)
    settings.OLLAMA_BLUE_MODEL = os.environ.get("OLLAMA_BLUE_MODEL", settings.OLLAMA_BLUE_MODEL)
    settings.OLLAMA_BLUE_TARGET_MODEL = os.environ.get("OLLAMA_BLUE_TARGET_MODEL", settings.OLLAMA_BLUE_TARGET_MODEL)
    settings.OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL)
    settings.OLLAMA_BASE_TARGET_MODEL = os.environ.get("OLLAMA_BASE_TARGET_MODEL", settings.OLLAMA_BASE_TARGET_MODEL)
    settings.OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", settings.OLLAMA_BASE_URL)

    return model_map


async def _ollama_model_status(base_url: str, models: list[str]) -> dict[str, bool]:
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(f"{base_url.rstrip('/')}/api/tags")
        resp.raise_for_status()
        installed = {
            str(row.get("name") or "")
            for row in (resp.json().get("models") or [])
            if row.get("name")
        }
    return {
        model: model in installed or (":" not in model and f"{model}:latest" in installed)
        for model in models
        if model
    }


async def _target_health(target_url: str, health_url: str | None = None) -> str:
    health_url = (health_url or "").strip() or target_url.rstrip("/")
    if not health_url.startswith(("http://", "https://")):
        raise ValueError("target health URL must start with http:// or https://")
    if not (health_url or "").strip():
        health_url = target_url.rstrip("/")
    if health_url == target_url.rstrip("/"):
        if health_url.endswith("/chat"):
            health_url = health_url[: -len("/chat")] + "/health"
        else:
            health_url = health_url + "/health"
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(health_url)
        resp.raise_for_status()
        return resp.text[:500]


def _write_integrated_report(
    final_state: dict[str, Any],
    out_dir: Path,
    ts: str,
    *,
    target_url: str,
    target_provider: str,
) -> Path:
    """Write a compact machine-readable + human-readable integration report."""
    summary = _short_summary(final_state)
    p1 = final_state.get("phase1_result", {}) or {}
    p2 = final_state.get("phase2_result", {}) or {}
    p3 = final_state.get("phase3_result", {}) or {}
    p4 = final_state.get("phase4_result", {}) or {}

    path = out_dir / f"finetuned_integrated_report_{ts}.md"
    lines = [
        f"# finetuned integrated pipeline report ({ts})",
        "",
        "## summary",
        "```json",
        json.dumps(summary, ensure_ascii=False, indent=2),
        "```",
        "",
        "## model routing",
        f"- red: {os.getenv('OLLAMA_RED_MODEL', '')}",
        f"- judge: {os.getenv('OLLAMA_JUDGE_MODEL', '')}",
        f"- blue: {os.getenv('OLLAMA_BLUE_MODEL', '')}",
        f"- target_url: {target_url}",
        f"- target_provider: {target_provider}",
        f"- target_model: {os.getenv('OLLAMA_MODEL', '') if target_provider in {'ollama_chat', 'ollama_generate'} else 'external adapter; OLLAMA_MODEL unused'}",
        "",
        "## artifacts",
        f"- phase1_total_scanned: {p1.get('total_scanned')}",
        f"- phase2_results: {len(p2.get('results', []) or [])}",
        f"- phase3_defense_files: {len(p3.get('defense_json_files', []) or [])}",
        f"- phase4_total_tested: {p4.get('total_tested')}",
        f"- phase4_safe: {p4.get('safe')}",
        f"- phase4_unsafe: {p4.get('unsafe')}",
        "",
        "## defense files",
    ]
    defense_files = p3.get("defense_json_files", []) or []
    if defense_files:
        lines.extend(f"- {rel}" for rel in defense_files)
    else:
        lines.append("- none")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


async def _main(args: argparse.Namespace) -> int:
    if not args.target_url.startswith(("http://localhost", "http://127.0.0.1")) and not args.allow_non_local_target:
        print("[ERROR] non-local target blocked. Use testbed URL or pass --allow-non-local-target explicitly.")
        return 2

    model_map = _apply_env_model_routing(args)
    adapter_config = TargetAdapterConfig.from_input(
        target_url=args.target_url,
        api_key=args.target_api_key,
        provider=args.target_provider,
        model=args.target_model,
    )
    target_model_label = (
        model_map["target"]
        if adapter_config.resolved_provider in {"ollama_chat", "ollama_generate"}
        else f"external adapter ({adapter_config.resolved_provider}); OLLAMA_MODEL unused"
    )

    print("=" * 72)
    print("  AgentShield Fine-tuned Integrated Pipeline")
    print("=" * 72)
    print(f"  target_url: {args.target_url}")
    print(f"  red:        {model_map['red']}")
    print(f"  judge:      {model_map['judge']}")
    print(f"  blue:       {model_map['blue']}")
    print(f"  target:     {target_model_label}")
    print(f"  ollama:     {model_map['ollama_base_url']}")
    print(f"  category:   {args.category or 'ALL'}")
    print(f"  max_attacks:{args.max_attacks if args.max_attacks is not None else 'ALL'}")
    print(f"  p2_rounds:  {args.phase2_rounds if args.phase2_rounds is not None else 'DEFAULT'}")
    print()

    if args.skip_target_health:
        print("[target] health skipped")
    else:
        try:
            health = await _target_health(args.target_url, args.target_health_url)
            print(f"[target] health ok: {health}")
        except Exception as exc:
            print(f"[ERROR] target health failed: {exc}")
            return 2

    if args.check_models:
        status = await _ollama_model_status(
            model_map["ollama_base_url"],
            [model_map["red"], model_map["judge"], model_map["blue"]],
        )
        print(f"[ollama] model_status={status}")
        missing = [name for name, ok in status.items() if not ok]
        if missing and not args.allow_missing_models:
            print(f"[ERROR] missing Ollama models: {missing}")
            return 2

    session_id = args.session_id or str(uuid.uuid4())
    print(f"[INFO] [{_log_ts()}] session_id={session_id}")
    print("[INFO] Phase1 -> Phase2 -> Phase3 -> Phase4 start")

    await _ensure_test_session(session_id, args.target_url)
    phase1_result_printer = _make_phase1_result_printer()

    with _patched_phase1_loader(
        category=args.category,
        max_attacks=args.max_attacks,
        shuffle=args.shuffle,
        seed=args.seed,
    ):
        with _patched_phase2_rounds(args.phase2_rounds):
            with _patched_llm_runtime(args.llm_timeout, verbose=args.verbose_trace):
                final_state = await run_scan(
                    session_id=session_id,
                    target_url=args.target_url,
                    target_config={
                        "provider": args.target_provider,
                        "model": args.target_model,
                        "api_key": args.target_api_key,
                    },
                    phase1_result_callback=phase1_result_printer,
                )

    summary = _short_summary(final_state)
    print(f"\n[INFO] [{_log_ts()}] === SUMMARY ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    out_dir = PROJECT_ROOT / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    state_path = out_dir / f"finetuned_integrated_state_{ts}.json"
    state_path.write_text(json.dumps(final_state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    review_path = _write_review_log(final_state, out_dir, ts)
    report_path = _write_integrated_report(
        final_state,
        out_dir,
        ts,
        target_url=args.target_url,
        target_provider=adapter_config.resolved_provider,
    )

    print(f"[saved] state:  {state_path}")
    print(f"[saved] review: {review_path}")
    print(f"[saved] report: {report_path}")
    print("[INFO] DB/Chroma writes are handled by phase nodes and existing persistence hooks.")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the full fine-tuned AgentShield pipeline against local testbed.")
    parser.add_argument(
        "--target-url",
        default=os.getenv("RED_CAMPAIGN_TARGET_URL") or os.getenv("TARGET_URL") or "http://localhost:8010/chat",
    )
    parser.add_argument("--target-health-url", default=os.getenv("TARGET_HEALTH_URL") or None)
    parser.add_argument("--skip-target-health", action="store_true")
    parser.add_argument("--target-provider", default=None)
    parser.add_argument(
        "--target-model",
        default=None,
        help="특수 provider용 target model override. testbed 기본 실행에서는 비워두고 .env OLLAMA_MODEL을 사용한다.",
    )
    parser.add_argument("--target-api-key", default=None)
    parser.add_argument("--ollama-url", default=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))

    parser.add_argument("--session-id", default=None)
    parser.add_argument("--category", default=None)
    parser.add_argument("--max-attacks", type=int, default=8)
    parser.add_argument("--phase2-rounds", type=int, default=3)
    parser.add_argument("--shuffle", action="store_true")
    parser.add_argument("--seed", type=int, default=57)
    parser.add_argument("--llm-timeout", type=float, default=180.0)
    parser.add_argument("--verbose-trace", action="store_true")
    parser.add_argument("--output-dir", default="results")

    parser.add_argument("--check-models", action="store_true", default=True)
    parser.add_argument("--no-check-models", action="store_false", dest="check_models")
    parser.add_argument("--allow-missing-models", action="store_true")
    parser.add_argument("--allow-non-local-target", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main(parse_args())))
