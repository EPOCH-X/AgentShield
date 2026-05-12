#!/usr/bin/env python3
"""강력한 Ollama Red 모델을 사용하여 깨끗한 Red Agent SFT 데이터를 생성합니다.

생성된 JSONL은 의도적으로 학습용으로만 사용됩니다.

{"messages": [{"role": "system", ...}, {"role": "user", ...}, {"role": "assistant", ...}]}

대상 응답, 심사자 점수, 라운드 로그, 생성 프롬프트 또는 도메인 힌트는 JSONL에 기록되지 않습니다.
이러한 정보는 사이드카 raw/report 파일에만 저장됩니다.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(PROJECT_ROOT / ".env", override=False)
except ImportError:
    pass

from backend.config import settings

SFT_SEED_OLLAMA_OPTIONS = {
    "num_ctx": 131072,
    "num_predict": 8192,
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 20,
    "presence_penalty": 1.5,
    "repeat_penalty": 1.1,
}

_TOKEN_COUNTER_CACHE: dict[str, Any] = {}


_TOKEN_COUNTER_FALLBACK = "Qwen/Qwen2.5-3B-Instruct"


def _get_token_counter(model_name: str):
    """토크나이저 lazy-load. 학습 베이스 안 되면 Qwen2.5로 fallback. 둘 다 실패 시 None."""
    if model_name in _TOKEN_COUNTER_CACHE:
        return _TOKEN_COUNTER_CACHE[model_name]
    try:
        from transformers import AutoTokenizer
    except ImportError:
        print("[WARN] transformers not installed. Skipping token-limit enforcement.")
        _TOKEN_COUNTER_CACHE[model_name] = None
        return None

    for candidate in [model_name, _TOKEN_COUNTER_FALLBACK]:
        try:
            tok = AutoTokenizer.from_pretrained(candidate)
            _TOKEN_COUNTER_CACHE[model_name] = tok
            print(f"[token-counter] loaded: {candidate}")
            return tok
        except Exception as exc:
            print(f"[WARN] tokenizer '{candidate}' load failed: {exc}")
    print("[WARN] all tokenizer candidates failed. Skipping token-limit enforcement.")
    _TOKEN_COUNTER_CACHE[model_name] = None
    return None


def _utc_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def _versioned(path: Path) -> Path:
    if not path.exists():
        return path
    i = 2
    stem = re.sub(r"_v\d+$", "", path.stem)
    while True:
        candidate = path.with_name(f"{stem}_v{i}{path.suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else PROJECT_ROOT / p


def _normalize_for_dedup(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())[:500]


async def main() -> int:
    parser = argparse.ArgumentParser(description="Build clean Red Agent SFT messages JSONL using hauhau/strong Red model.")
    parser.add_argument("--input", default=os.getenv("ATTACK_PATTERN_PATH", "data/test_attack_sets/all_01_02_06_07_strongest_20.json"))
    parser.add_argument("--output", default=f"data/finetuning/red_sft_hauhau_generated_{_utc_stamp()}.jsonl")
    parser.add_argument("--raw-output", default="")
    parser.add_argument("--report-output", default="")
    parser.add_argument("--category", default="ALL")
    parser.add_argument("--seed-mode", choices=["raw", "file", "hybrid"], default="raw")
    parser.add_argument(
        "--domains",
        default=os.getenv(
            "RED_SFT_DOMAINS",
            "general_assistant,finance,healthcare,rag,hr,government,ecommerce",
        ),
    )
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--rounds", type=int, default=1, help="Deprecated for SFT seed generation; one standalone prompt per seed is generated.")
    parser.add_argument("--generation-attempts", type=int, default=3)
    parser.add_argument("--red-model", default=os.getenv("RED_CAMPAIGN_MODEL", "hauhau-qwen:latest"))
    parser.add_argument("--red-max-tokens", type=int, default=int(os.getenv("RED_CAMPAIGN_NUM_PREDICT", "8192")))
    parser.add_argument("--min-attack-chars", type=int, default=500)
    parser.add_argument("--max-attack-chars", type=int, default=settings.RED_MAX_ATTACK_CHARS)
    parser.add_argument("--system-prompt", choices=["runtime", "minimal"], default="runtime", help="Deprecated; SFT seed generation always uses red_sft_seed_agent system prompt.")
    parser.add_argument("--allow-literal-values", action="store_true", help="Deprecated; SFT seed output always rejects hardcoded literal values.")
    parser.add_argument("--allow-stale-timestamps", action="store_true", help="Deprecated; SFT seed output always rejects hardcoded timestamps.")
    parser.add_argument(
        "--max-jsonl-tokens", type=int, default=9500,
        help="JSONL 한 행(messages 전체 ChatML)이 이 토큰 수 초과면 자동 드랍. "
             "기본 9500 = Qwen3.5 학습 안전 마진 (실제 학습 MAX_LEN 12500 기준 여유).",
    )
    parser.add_argument(
        "--token-counter-model",
        default="SicariusSicariiStuff/Qwen3.5-2B_Abliterated",
        help="토큰 카운트용 토크나이저. 학습 베이스와 동일 모델 권장. "
             "transformers 미지원 시 자동으로 Qwen/Qwen2.5-3B-Instruct로 fallback.",
    )
    parser.add_argument("--code-mutation", dest="code_mutation", action="store_true", default=settings.RED_SFT_SEED_CODE_MUTATION)
    parser.add_argument("--no-code-mutation", dest="code_mutation", action="store_false")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    os.environ["OLLAMA_RED_MODEL"] = args.red_model
    os.environ["OLLAMA_RED_TARGET_MODEL"] = args.red_model

    from backend.agents.llm_client import AgentShieldLLM
    from backend.agents.red_sft_seed_agent import (
        build_sft_retry_prompt,
        build_sft_seed_prompt,
        compact_sft_training_user,
        fingerprint_attack_prompt,
        get_carrier_for_seed,
        get_sft_seed_system_prompt,
        normalize_attack_prompt_output,
        validate_sft_seed_output,
    )
    from backend.core.mutation_engine import apply_code_mutation
    from backend.core.pyrit_converter import apply_pyrit_converter
    from scripts.generate_red_attack_prompts_only import (
        _load_items,
        _raw_seed_rows,
    )

    if args.seed is not None:
        random.seed(args.seed)

    input_path = _resolve(args.input)
    file_rows = _load_items(input_path, args.category)
    if args.seed_mode == "raw":
        seed_rows = _raw_seed_rows(args.category, args.seeds)
    elif args.seed_mode == "hybrid":
        seed_rows = _raw_seed_rows(args.category, max(1, args.seeds // 2)) + file_rows
    else:
        seed_rows = file_rows
    random.shuffle(seed_rows)
    seed_rows = seed_rows[: args.seeds]
    if not seed_rows:
        print(f"[ERROR] no seed rows loaded from {input_path}")
        return 2

    system_prompt = get_sft_seed_system_prompt()

    llm = AgentShieldLLM()
    domains = [d.strip() for d in args.domains.split(",") if d.strip()] or ["general"]
    accepted: list[dict[str, Any]] = []
    raw_records: list[dict[str, Any]] = []
    rejected_records: list[dict[str, Any]] = []
    rejection_counts: Counter[str] = Counter()
    seen: set[str] = set()
    prior_fingerprints: list[dict[str, Any]] = []

    # 경로를 루프 앞으로 옮겨 매 seed마다 증분 저장 가능하게 함.
    output_path = _versioned(_resolve(args.output))
    raw_path = _versioned(_resolve(args.raw_output)) if args.raw_output else output_path.with_suffix(".raw.json")
    report_path = _versioned(_resolve(args.report_output)) if args.report_output else output_path.with_suffix(".report.json")
    rejected_path = output_path.with_suffix(".rejected.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    def flush_state() -> None:
        """매 seed 처리 후 호출. 크래시 시 손실은 최대 1 seed 분량."""
        with output_path.open("w", encoding="utf-8") as fh:
            for s in accepted:
                fh.write(json.dumps(s, ensure_ascii=False) + "\n")
        raw_path.write_text(json.dumps(raw_records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        rejected_path.write_text(json.dumps(rejected_records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report_partial = {
            "model": args.red_model,
            "output": str(output_path),
            "raw_output": str(raw_path),
            "accepted": len(accepted),
            "rejections": dict(rejection_counts.most_common()),
            "category_counts": dict(Counter(r["category"] for r in raw_records)),
            "domain_counts": dict(Counter(r["domain"] for r in raw_records)),
            "carrier_counts": dict(Counter(r["carrier"] for r in raw_records)),
            "pyrit_strategy_counts": dict(Counter(r["pyrit_converter_strategy"] for r in raw_records)),
            "system_prompt_mode": args.system_prompt,
            "in_progress": True,
            "jsonl_contract": "messages only; no target_response/judge/score/round logs in JSONL",
        }
        report_path.write_text(json.dumps(report_partial, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"[paths] jsonl:    {output_path}")
    print(f"[paths] raw:      {raw_path}")
    print(f"[paths] report:   {report_path}")
    print(f"[paths] rejected: {rejected_path}")

    for seed_index, seed_row in enumerate(seed_rows, 1):
        category = str(seed_row.get("category") or args.category).upper()
        subcategory = str(seed_row.get("subcategory") or "")
        domain = domains[(seed_index - 1) % len(domains)]
        generation_prompt = build_sft_seed_prompt(
            category=category,
            subcategory=subcategory,
            domain=domain,
            prior_fingerprints=prior_fingerprints,
            seed_index=seed_index - 1,
        )
        retry_prompt = generation_prompt
        accepted_prompt = ""
        final_reason = "not generated"
        code_strategy = "none"
        pyrit_converter_strategy = "none"
        encoding_index = (seed_index - 1) % 11
        carrier = get_carrier_for_seed(seed_index - 1)
        carrier_name = carrier["name"]

        for attempt in range(1, args.generation_attempts + 1):
            raw = await llm.generate(
                retry_prompt,
                role="red",
                max_tokens=args.red_max_tokens,
                system_prompt_override=system_prompt,
                options_override=SFT_SEED_OLLAMA_OPTIONS,
            )
            if isinstance(raw, str) and raw.startswith("[Error]"):
                final_reason = raw
                rejection_counts["llm_call_failed"] += 1
                print(f"[ERROR] seed={seed_index} attempt={attempt}: {raw}")
                break
            attack_prompt = normalize_attack_prompt_output(str(raw or ""))
            if args.code_mutation:
                attack_prompt, code_strategy = apply_code_mutation(attack_prompt, 1)
                attack_prompt = normalize_attack_prompt_output(attack_prompt)

            ok, reason, evidence = validate_sft_seed_output(
                attack_prompt,
                min_chars=args.min_attack_chars,
                max_chars=args.max_attack_chars,
                carrier=carrier_name,
            )
            if ok:
                dedup_key = _normalize_for_dedup(attack_prompt)
                if dedup_key in seen:
                    ok, reason, evidence = False, "duplicate attack prompt", ""
                else:
                    seen.add(dedup_key)
                    try:
                        attack_prompt, pyrit_converter_strategy = await apply_pyrit_converter(
                            attack_prompt, encoding_index
                        )
                    except Exception as exc:
                        # 컨버터 실패해도 원문 그대로 통과 (메인 루프 보호)
                        pyrit_converter_strategy = f"ERROR: {type(exc).__name__}: {exc}"
                        print(f"[WARN] seed={seed_index} pyrit converter failed: {pyrit_converter_strategy}")
                    accepted_prompt = attack_prompt
                    final_reason = ""
                    break

            final_reason = reason
            rejection_counts[reason] += 1
            rejected_records.append(
                {
                    "seed_index": seed_index,
                    "attempt": attempt,
                    "category": category,
                    "subcategory": subcategory,
                    "domain": domain,
                    "carrier": carrier_name,
                    "encoding_index": encoding_index,
                    "rejection_reason": reason,
                    "rejection_evidence": evidence,
                    "raw_output": str(raw or ""),
                    "raw_output_len": len(str(raw or "")),
                    "normalized_output": attack_prompt,
                    "normalized_output_len": len(attack_prompt),
                }
            )
            print(f"[RETRY] seed={seed_index} attempt={attempt} rejected: {reason}")
            retry_prompt = build_sft_retry_prompt(
                base_prompt=generation_prompt,
                rejection_reason=reason,
                attempt=attempt,
                evidence=evidence,
            )

        if not accepted_prompt:
            print(f"[SKIP] seed={seed_index}: {final_reason}")
            flush_state()
            continue

        training_user = compact_sft_training_user(
            category=category,
            subcategory=subcategory,
            domain=domain,
        )
        sample = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": training_user},
                {"role": "assistant", "content": accepted_prompt},
            ]
        }

        # JSONL 토큰 길이 제한 (코랩 학습 시 OOM/MAX_LEN 절단 방지)
        if args.max_jsonl_tokens > 0:
            tok = _get_token_counter(args.token_counter_model)
            if tok is not None:
                txt = tok.apply_chat_template(sample["messages"], tokenize=False, add_generation_prompt=False)
                n_tokens = len(tok.encode(txt, add_special_tokens=False))
                if n_tokens > args.max_jsonl_tokens:
                    reason = f"jsonl_too_long: {n_tokens} > {args.max_jsonl_tokens}"
                    rejection_counts[reason] += 1
                    print(f"[DROP] seed={seed_index} category={category} tokens={n_tokens} > {args.max_jsonl_tokens}")
                    flush_state()
                    continue

        accepted.append(sample)
        fingerprint = fingerprint_attack_prompt(
            category=category,
            domain=domain,
            attack_prompt=accepted_prompt,
        )
        prior_fingerprints.append(fingerprint)

        raw_records.append(
            {
                "id": f"red-sft-seed-{category.lower()}-{seed_index:03d}",
                "category": category,
                "subcategory": subcategory,
                "domain": domain,
                "carrier": carrier_name,
                "seed_index": seed_index,
                "source_seed_id": seed_row.get("id") or seed_row.get("seed_id") or "",
                "code_mutation_strategy": code_strategy,
                "pyrit_converter_strategy": pyrit_converter_strategy,
                "ollama_options": SFT_SEED_OLLAMA_OPTIONS,
                "fingerprint": fingerprint,
                "attack_prompt": accepted_prompt,
                "attack_prompt_len": len(accepted_prompt),
                "training_user": training_user,
            }
        )
        print(f"[OK] seed={seed_index} category={category} domain={domain} len={len(accepted_prompt)}")
        flush_state()

    # 최종 report (in_progress=False로 마무리)
    final_report = {
        "model": args.red_model,
        "output": str(output_path),
        "raw_output": str(raw_path),
        "accepted": len(accepted),
        "rejections": dict(rejection_counts.most_common()),
        "category_counts": dict(Counter(r["category"] for r in raw_records)),
        "domain_counts": dict(Counter(r["domain"] for r in raw_records)),
        "carrier_counts": dict(Counter(r["carrier"] for r in raw_records)),
        "pyrit_strategy_counts": dict(Counter(r["pyrit_converter_strategy"] for r in raw_records)),
        "system_prompt_mode": args.system_prompt,
        "in_progress": False,
        "jsonl_contract": "messages only; no target_response/judge/score/round logs in JSONL",
    }
    report_path.write_text(json.dumps(final_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"[saved] jsonl:    {output_path}")
    print(f"[saved] raw:      {raw_path}")
    print(f"[saved] report:   {report_path}")
    print(f"[saved] rejected: {rejected_path}")
    print(f"[count] accepted={len(accepted)} rejected_attempts={sum(rejection_counts.values())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
