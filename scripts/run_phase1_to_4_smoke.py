#!/usr/bin/env python3
"""
Phase1~4 전체 그래프를 로컬에서 한 번 실행해보는 임시 스모크 스크립트.

사용:
  python scripts/run_phase1_to_4_smoke.py --target-url http://localhost:8010/chat
  python scripts/run_phase1_to_4_smoke.py --session-id smoke-001

Phase3~4만 (시드 JSON — 예: curated vulnerable 패턴 파일):
  python scripts/run_phase1_to_4_smoke.py --phase34-only \\
    --phase34-input-json data/attack_patterns/curated_from_smoke_20260501_131512_vulnerable_p1p2.json \\
    --target-url http://localhost:8010/chat --save-full

--save-full 시 results/ 에 다음 패턴으로 저장됩니다:
  phase1to4_smoke_*.json / phase3to4_smoke_*.json — 루트에 smoke_llm_provenance
    (ollama_blue_target_model, ollama_blue_model, ollama_base_url, recorded_at)
  phase1to4_review_*.md / phase3to4_review_*.md — 상단에 동일 Blue/Ollama 요약
  *.run.meta.json — OLLAMA_BLUE_* 등 실행 컨텍스트 (기존과 동일)

테스트 후 삭제:
  rm scripts/run_phase1_to_4_smoke.py
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime
import json
import logging
import os
import random
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.phase34_seed import load_phase34_seed
from backend.graph.llm_security_graph import run_scan, run_scan_phase34


def _fs_slug(name: str, *, max_len: int = 80) -> str:
    """파일명에 넣기 안전한 짧은 슬러그(: / 등은 `-` 로 통일)."""
    s = (name or "unknown").strip()
    for ch in '\\:*?"<>|':
        s = s.replace(ch, "-")
    s = s.replace("/", "-").replace(" ", "_")
    while "__" in s:
        s = s.replace("__", "_")
    s = s.strip("._-")
    if len(s) > max_len:
        s = s[:max_len].rstrip("._-")
    return s or "unknown"


def _blue_tags_from_env() -> tuple[str, str]:
    """(OLLAMA_BLUE_TARGET_MODEL, OLLAMA_BLUE_MODEL) 설정값."""
    try:
        from backend.config import settings as _settings

        target = os.getenv("OLLAMA_BLUE_TARGET_MODEL") or getattr(
            _settings, "OLLAMA_BLUE_TARGET_MODEL", ""
        )
        blue = os.getenv("OLLAMA_BLUE_MODEL") or getattr(_settings, "OLLAMA_BLUE_MODEL", "")
    except Exception:
        target = os.getenv("OLLAMA_BLUE_TARGET_MODEL", "")
        blue = os.getenv("OLLAMA_BLUE_MODEL", "")
    return (str(target or "").strip(), str(blue or "").strip())


def _ollama_base_url_for_meta() -> str:
    try:
        from backend.config import settings as _settings

        return str(os.getenv("OLLAMA_BASE_URL") or getattr(_settings, "OLLAMA_BASE_URL", "") or "")
    except Exception:
        return str(os.getenv("OLLAMA_BASE_URL", "") or "")


def _inject_smoke_llm_provenance(state: dict) -> None:
    """저장되는 full state / export용으로 Blue·Ollama 컨텍스트를 상태 루트에 남긴다."""
    blue_target, blue_model = _blue_tags_from_env()
    state["smoke_llm_provenance"] = {
        "ollama_blue_target_model": blue_target or None,
        "ollama_blue_model": blue_model or None,
        "ollama_base_url": _ollama_base_url_for_meta() or None,
        "recorded_at": datetime.now().isoformat(timespec="seconds"),
    }


def _build_artifact_stem(ts: str, args: argparse.Namespace) -> str:
    """
    결과 파일 공통 접미사: <YYYYMMDD_HHMMSS>_<blue_tag>_<seed_tag>
    """
    blue_raw, _ = _blue_tags_from_env()
    blue = _fs_slug(blue_raw or "unknown-blue", max_len=48)
    if args.phase34_only:
        if args.phase34_input_json:
            seed = _fs_slug(Path(args.phase34_input_json).stem, max_len=56)
        else:
            seed = "no-seed-path"
    else:
        cat = args.category or "all"
        mx = args.max_attacks if args.max_attacks is not None else "all"
        seed = _fs_slug(f"cat-{cat}-max{mx}", max_len=56)
    return f"{ts}_{blue}_{seed}"


def _write_run_meta(
    meta_path: Path,
    args: argparse.Namespace,
    state_path: Path,
    stem_suffix: str,
) -> None:
    blue_target, blue_model = _blue_tags_from_env()
    ollama_base = _ollama_base_url_for_meta()
    try:
        rel_state = str(state_path.relative_to(PROJECT_ROOT))
    except ValueError:
        rel_state = str(state_path)
    payload = {
        "artifact_stem": stem_suffix,
        "saved_state_json": rel_state,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "script": "scripts/run_phase1_to_4_smoke.py",
        "argv": sys.argv.copy(),
        "phase34_only": bool(args.phase34_only),
        "phase34_input_json": args.phase34_input_json,
        "ollama_blue_target_model": blue_target,
        "ollama_blue_model": blue_model,
        "ollama_base_url": str(ollama_base or ""),
        "target_url": args.target_url,
        "target_provider": args.target_provider,
        "target_model": args.target_model,
    }
    meta_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _log_ts() -> str:
    """로컬 시각(초). [INFO]/[TRACE]/[WARN] 공통."""
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def _trace(enabled: bool, msg: str) -> None:
    if enabled:
        print(f"[TRACE] [{_log_ts()}] {msg}", flush=True)


def _make_phase1_result_printer():
    result_counter = {"n": 0}

    def _print_result(result: dict) -> None:
        result_counter["n"] += 1
        idx = result_counter["n"]
        category = result.get("category", "?")
        subcategory = result.get("subcategory", "?")
        judgment = result.get("judgment", "?")

        if judgment == "vulnerable":
            print(f"  [{idx}] {category}/{subcategory} -> 🔴 vulnerable", flush=True)
        elif judgment == "safe":
            print(f"  [{idx}] {category}/{subcategory} -> 🟢 safe", flush=True)
        elif judgment == "ambiguous":
            print(f"  [{idx}] {category}/{subcategory} -> 🟡 ambiguous", flush=True)
        else:
            source = result.get("error_source", "Unknown")
            reason = result.get("failure_mode", result.get("detail", "unknown"))
            print(f"  [{idx}] {category}/{subcategory} -> ❌ error [{source}] {reason}", flush=True)

    return _print_result


# ── Phase1 어댑터 패치 ────────────────────────────────────────────────────────

@contextmanager
def _patched_phase1_target_for_ollama(verbose: bool = True):
    """
    Phase1 기본 target 호출을 Ollama /api/chat 형식으로 맞춘다.

    [수정] resp_len=0 시 reason=empty_response 출력
    [수정] raise_for_status() 실패 시 reason=http_{status} 출력 후 재raise
           → phase1_scanner의 재시도 로직이 이어서 처리
    """
    from backend.config import settings
    from backend.core import phase1_scanner

    original_run_phase1 = phase1_scanner.run_phase1

    async def wrapped_run_phase1(
        session_id: str,
        target_url: str,
        category: str | None = None,
        target_config: dict | None = None,
        send_fn=None,
        llm=None,
        on_result=None,
    ):
        # ── 결과 실시간 출력 카운터 ────────────────────────────────────────
        result_counter = {"n": 0}

        def _print_result(result: dict) -> None:
            result_counter["n"] += 1
            idx        = result_counter["n"]
            category   = result.get("category", "?")
            sub        = result.get("subcategory", "?")
            judgment   = result.get("judgment", "?")

            if judgment == "vulnerable":
                print(f"  [{idx}] {category}/{sub} → 🔴 vulnerable", flush=True)
            elif judgment == "safe":
                print(f"  [{idx}] {category}/{sub} → 🟢 safe", flush=True)
            elif judgment == "ambiguous":
                print(f"  [{idx}] {category}/{sub} → 🟡 ambiguous", flush=True)
            else:
                # ── 에러: error_source / failure_mode 상세 출력 ──────────
                source  = result.get("error_source", "Unknown")
                reason  = result.get("failure_mode", result.get("detail", "unknown"))
                print(f"  [{idx}] {category}/{sub} → ❌ error [{source}] {reason}", flush=True)

        # ── 커스텀 send_fn: Ollama /api/chat 형식으로 변환 + 502/503 재시도 ──
        _RETRYABLE_HTTP = {502, 503}
        _SEND_MAX_RETRIES = 3

        async def ollama_send_fn(client, prompt_text: str) -> str:
            # http post ->/<- 로그는 _patched_phase2_target_for_ollama의
            # OllamaCompatibleAsyncClient가 전담 → 여기서 중복 출력 방지
            for attempt in range(1, _SEND_MAX_RETRIES + 1):
                _trace(verbose, f"phase1 target request start (prompt_len={len(prompt_text)}, attempt={attempt}/{_SEND_MAX_RETRIES})")

                try:
                    resp = await client.post(
                        target_url,
                        json={
                            "messages": [{"role": "user", "content": prompt_text}],
                        },
                    )
                except Exception as conn_err:
                    _trace(verbose, f"phase1 target connection error: {conn_err} (attempt {attempt}/{_SEND_MAX_RETRIES})")
                    if attempt < _SEND_MAX_RETRIES:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    raise

                # 502/503: 지수 백오프 후 재시도
                if resp.status_code in _RETRYABLE_HTTP:
                    try:
                        err_type = resp.json().get("error", f"http_{resp.status_code}")
                    except Exception:
                        err_type = f"http_{resp.status_code}"
                    _trace(verbose, f"phase1 target request done (resp_len=0, reason={err_type})")
                    if attempt < _SEND_MAX_RETRIES:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    resp.raise_for_status()

                try:
                    resp.raise_for_status()
                except Exception:
                    _trace(verbose, f"phase1 target request done (resp_len=0, reason=http_{resp.status_code})")
                    raise

                data = resp.json()
                content = str(data.get("message", {}).get("content", "")).strip()
                if not content:
                    content = str(data.get("content", "")).strip()
                if not content:
                    content = str(data.get("response", "")).strip()

                if not content:
                    _trace(verbose, f"phase1 target request done (resp_len=0, reason=empty_response, raw={repr(str(data)[:100])})")
                else:
                    _trace(verbose, f"phase1 target request done (resp_len={len(content)}, preview={repr(content[:50])})")

                return content

            return ""

        effective_send_fn = send_fn or ollama_send_fn
        effective_on_result = on_result or _print_result

        _trace(verbose, f"phase1 start (session_id={session_id}, category={category or 'ALL'})")

        result = await original_run_phase1(
            session_id=session_id,
            target_url=target_url,
            category=category,
            target_config=target_config,
            send_fn=effective_send_fn,
            llm=llm,
            on_result=effective_on_result,
        )

        _trace(
            verbose,
            "phase1 done "
            f"(total={result.get('total_scanned')}, "
            f"vuln={len(result.get('vulnerable_attacks', []) or [])}, "
            f"safe={len(result.get('safe_attacks', []) or [])})",
        )
        return result

    phase1_scanner.run_phase1 = wrapped_run_phase1
    try:
        yield
    finally:
        phase1_scanner.run_phase1 = original_run_phase1


# ── Phase2 어댑터 패치 ────────────────────────────────────────────────────────

@contextmanager
def _patched_phase2_target_for_ollama(target_url: str, verbose: bool = True):
    """Phase2의 target 호출 payload를 Ollama /api/chat 형식으로 맞춘다."""
    import httpx

    from backend.config import settings
    from backend.core import phase2_red_agent

    original_async_client = phase2_red_agent.httpx.AsyncClient
    original_httpx_client = httpx.AsyncClient

    normalized_target_url = target_url.rstrip("/")

    class OllamaCompatibleAsyncClient(original_httpx_client):
        async def post(self, url, *args, **kwargs):
            payload = kwargs.get("json")
            normalized_url = str(url).rstrip("/")
            was_converted = False
            payload_mode = "passthrough"
            original_prompt_len = None
            transformed_prompt_len = None
            
            # Phase2의 "타겟 모델 호출"만 변환하고,
            # /api/generate(Agent LLM 호출)는 건드리지 않는다.
            if (
                normalized_url == normalized_target_url
                and isinstance(payload, dict)
                and "prompt" in payload
                and "messages" not in payload
            ):
                prompt_text = str(payload.get("prompt", ""))
                original_prompt_len = len(prompt_text)
                transformed_prompt_len = len(prompt_text)
                _trace(
                    verbose,
                    f"[CONVERT] {normalized_target_url}: prompt→messages "
                    f"(prompt_len={len(prompt_text)})"
                )
                kwargs["json"] = {
                    "messages": [{"role": "user", "content": prompt_text}],
                }
                was_converted = True
                payload_mode = "prompt_to_messages"
            else:
                # 변환 안 된 이유 로깅
                if normalized_url == normalized_target_url:
                    has_prompt = isinstance(payload, dict) and "prompt" in payload
                    has_messages = isinstance(payload, dict) and "messages" in payload
                    if has_messages:
                        payload_mode = "already_messages"
                        try:
                            msg_list = payload.get("messages") or []
                            if isinstance(msg_list, list) and msg_list:
                                last_msg = msg_list[-1] if isinstance(msg_list[-1], dict) else {}
                                transformed_prompt_len = len(str(last_msg.get("content", "")))
                        except Exception:
                            transformed_prompt_len = None
                    _trace(
                        verbose,
                        f"[NO-CONVERT] {normalized_target_url}: prompt={has_prompt}, messages={has_messages}, mode={payload_mode}"
                    )
            
            _trace(verbose, f"→ POST {url}")
            try:
                response = await super().post(url, *args, **kwargs)
                _trace(
                    verbose,
                    f"← POST {url} status={response.status_code} "
                    f"converted={was_converted} payload_mode={payload_mode} "
                    f"original_prompt_len={original_prompt_len} transformed_prompt_len={transformed_prompt_len} "
                    f"content_len={len(response.content)}"
                )
                # HTTP 에러 코드 명시적 로깅
                if response.status_code >= 400:
                    try:
                        error_text = response.text[:500]
                    except:
                        error_text = f"<unparseable: {response.status_code}>"
                    _trace(verbose, f"[ERROR] {response.status_code}: {error_text}")
                return response
            except Exception as e:
                _trace(verbose, f"[EXCEPTION] POST {url}: {type(e).__name__}: {str(e)[:200]}")
                raise

    phase2_red_agent.httpx.AsyncClient = OllamaCompatibleAsyncClient
    try:
        yield
    finally:
        phase2_red_agent.httpx.AsyncClient = original_async_client


# ── Phase1 로더 패치 ──────────────────────────────────────────────────────────

@contextmanager
def _patched_phase1_loader(
    *,
    category: str | None,
    max_attacks: int | None,
    shuffle: bool,
    seed: int | None,
):
    """phase1_scanner의 공격 로더를 테스트 옵션에 맞게 임시 패치."""
    from backend.core import phase1_scanner

    original_loader = phase1_scanner._load_attacks

    async def wrapped_loader(
        requested_category: str | None = None, max_attacks_inner: int | None = None
    ) -> list[dict]:
        selected_category = category if category is not None else requested_category
        attacks = await original_loader(selected_category, max_attacks_inner)
        if shuffle:
            rng = random.Random(seed)
            rng.shuffle(attacks)
        effective_max = max_attacks if max_attacks is not None else max_attacks_inner
        if effective_max is not None and effective_max >= 0:
            attacks = attacks[:effective_max]
        print(
            f"[INFO] [{_log_ts()}] phase1 attack file/db load done: {len(attacks)} items",
            flush=True,
        )
        return attacks

    phase1_scanner._load_attacks = wrapped_loader
    try:
        yield
    finally:
        phase1_scanner._load_attacks = original_loader


# ── Phase2 라운드 패치 ────────────────────────────────────────────────────────

@contextmanager
def _patched_phase2_rounds(rounds: int | None):
    """settings.PHASE2_MAX_ROUNDS를 테스트 실행 동안만 임시 변경."""
    if rounds is None:
        yield
        return

    from backend.config import settings

    original_rounds = settings.PHASE2_MAX_ROUNDS
    settings.PHASE2_MAX_ROUNDS = rounds
    try:
        yield
    finally:
        settings.PHASE2_MAX_ROUNDS = original_rounds


# ── LLM 타임아웃 패치 ─────────────────────────────────────────────────────────

@contextmanager
def _patched_llm_runtime(timeout_sec: float | None, verbose: bool = True):
    """AgentShieldLLM.generate 호출에 trace + timeout을 강제한다."""
    if timeout_sec is None:
        yield
        return

    from backend.agents.llm_client import AgentShieldLLM

    original_generate = AgentShieldLLM.generate

    async def wrapped_generate(self, *args, **kwargs):
        role = kwargs.get("role", "base")
        prompt = args[0] if args else kwargs.get("prompt", "")
        _trace(verbose, f"llm.generate start role={role} prompt_len={len(str(prompt))}")
        try:
            result = await asyncio.wait_for(
                original_generate(self, *args, **kwargs), timeout=timeout_sec
            )
            _trace(verbose, f"llm.generate done role={role} resp_len={len(str(result))}")
            return result
        except asyncio.TimeoutError:
            _trace(verbose, f"llm.generate timeout role={role} after={timeout_sec:.1f}s")
            return f"[Error] LLM timeout after {timeout_sec:.1f}s"

    AgentShieldLLM.generate = wrapped_generate
    try:
        yield
    finally:
        AgentShieldLLM.generate = original_generate


# ── 결과 요약 / 저장 ──────────────────────────────────────────────────────────

def _unique_defense_ids_from_phase3_seed(final_state: dict) -> set[str]:
    """첫 Phase3 입력(취약 풀)의 고유 defense_id / test_result_id."""
    h = final_state.get("phase3_history") or []
    if h and isinstance(h[0], dict):
        rows = h[0].get("source_vulnerabilities") or []
    else:
        rows = (final_state.get("phase3_result") or {}).get("source_vulnerabilities") or []
    pool: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        did = str(row.get("defense_id") or "").strip()
        tid = str(row.get("test_result_id") or "").strip()
        if did:
            pool.add(did)
        elif tid:
            pool.add(tid)
    return pool


def _last_phase4_verdict_by_defense_id(final_state: dict) -> dict[str, str]:
    """phase4_history 순서대로 덮어써 defense_id별 최종 verdict(safe/unsafe)."""
    last: dict[str, str] = {}
    for entry in final_state.get("phase4_history") or []:
        if not isinstance(entry, dict):
            continue
        for d in entry.get("details") or []:
            if not isinstance(d, dict):
                continue
            did = str(d.get("defense_id") or "").strip()
            v = str(d.get("verdict") or "").strip()
            if did and v:
                last[did] = v
    if not last:
        p4 = final_state.get("phase4_result") or {}
        for d in p4.get("details") or []:
            if not isinstance(d, dict):
                continue
            did = str(d.get("defense_id") or "").strip()
            v = str(d.get("verdict") or "").strip()
            if did and v:
                last[did] = v
    return last


def _short_summary(final_state: dict) -> dict:
    p1 = final_state.get("phase1_result", {}) or {}
    p2 = final_state.get("phase2_result", {}) or {}
    p3 = final_state.get("phase3_result", {}) or {}
    p4 = final_state.get("phase4_result", {}) or {}
    phase1_vulnerable = int(p1.get("vulnerable_count") or 0)
    phase1_safe = int(p1.get("safe_count") or 0)
    phase1_ambiguous = int(p1.get("ambiguous_count") or 0)
    phase1_error = int(p1.get("error_count") or 0)
    phase2_results = [r for r in (p2.get("results", []) or []) if isinstance(r, dict)]
    phase2_counter = Counter(str(r.get("judgment") or "") for r in phase2_results)
    phase2_vulnerable = int(phase2_counter.get("vulnerable", 0))
    phase3_defenses_generated = int(
        p3.get("cumulative_defenses_generated", p3.get("defenses_generated") or 0)
    )
    phase3_failed = int(p3.get("cumulative_failed", p3.get("failed") or 0))
    phase3_total_input = int(
        p3.get("cumulative_total_vulnerabilities")
        or p3.get("initial_total_vulnerabilities")
        or (phase1_vulnerable + phase2_vulnerable)
        or 0
    )
    phase3_total_handled = phase3_defenses_generated + phase3_failed
    phase3_total_unhandled = max(
        phase3_total_input - phase3_total_handled,
        0,
    )

    pool_ids = _unique_defense_ids_from_phase3_seed(final_state)
    pool_n = len(pool_ids)
    if pool_n == 0:
        pool_n = int(p3.get("initial_total_vulnerabilities") or 0)
    last_verdicts = _last_phase4_verdict_by_defense_id(final_state)
    final_safe = sum(1 for did in pool_ids if last_verdicts.get(did) == "safe") if pool_ids else 0
    final_unsafe = sum(1 for did in pool_ids if last_verdicts.get(did) == "unsafe") if pool_ids else 0
    final_missing = len(pool_ids) - final_safe - final_unsafe if pool_ids else 0
    retry_rounds = len(final_state.get("phase3_history") or [])
    prov = final_state.get("smoke_llm_provenance")
    prov = prov if isinstance(prov, dict) else {}
    bt = prov.get("ollama_blue_target_model")
    bm = prov.get("ollama_blue_model")
    ob = prov.get("ollama_base_url")

    return {
        "phase4_to3_iteration": final_state.get("iteration"),
        "ollama_blue_target_model": bt,
        "ollama_blue_model": bm,
        "ollama_base_url": ob,
        "phase1_total_scanned": p1.get("total_scanned"),
        "phase1_vulnerable": phase1_vulnerable,
        "phase1_safe": phase1_safe,
        "phase1_ambiguous": phase1_ambiguous,
        "phase1_error": phase1_error,
        "phase2_total_results": len(phase2_results),
        "phase2_vulnerable": phase2_vulnerable,
        "phase2_safe": int(phase2_counter.get("safe", 0)),
        "phase2_ambiguous": int(phase2_counter.get("ambiguous", 0)),
        "phase2_error": int(phase2_counter.get("error", 0)),
        "phase2_generation_failed": int(phase2_counter.get("generation_failed", 0)),
        # 재시도마다 total_vulnerabilities 합산(예: 29+8+1=38). 고유 취약 풀 크기와 다름.
        "phase3_total_input": phase3_total_input,
        "phase3_blue_generation_slots_sum": phase3_total_input,
        "phase3_defenses_generated": phase3_defenses_generated,
        "phase3_failed": phase3_failed,
        "phase3_total_handled": phase3_total_handled,
        "phase3_total_unhandled": phase3_total_unhandled,
        "phase3_unique_vulnerability_count": pool_n,
        "phase3_phase4_retry_rounds": retry_rounds,
        "phase4_final_verdict_safe_count": final_safe,
        "phase4_final_verdict_unsafe_count": final_unsafe,
        "phase4_final_verdict_missing_count": max(final_missing, 0),
        "phase4_final_scorecard": f"총 {pool_n}건 중 safe {final_safe}건, unsafe {final_unsafe}건",
        "phase4_total_tested_cumulative": int(p4.get("cumulative_total_tested") or p4.get("total_tested") or 0),
        "phase4_safe_cumulative": int(p4.get("cumulative_safe") or p4.get("safe") or 0),
        "phase4_unsafe_cumulative": int(p4.get("cumulative_unsafe") or p4.get("unsafe") or 0),
        "phase4_total_tested_last_cycle": int(p4.get("total_tested") or 0),
        "phase4_safe_last_cycle": int(p4.get("safe") or 0),
        "phase4_unsafe_last_cycle": int(p4.get("unsafe") or 0),
        "phase4_passed_threshold_final": p4.get("passed_threshold"),
    }


def _defense_code_preview(payload: dict) -> str:
    return json.dumps(
        {
            "defended_response": payload.get("defended_response", ""),
            "defense_rationale": payload.get("defense_rationale", ""),
            "failure_mode": payload.get("failure_mode", ""),
        },
        ensure_ascii=False,
        indent=2,
    )


def _response_body_for_review(raw: str) -> str:
    """리뷰 MD에는 Ollama/Chat 전체 JSON 대신 assistant 본문만 넣는다."""
    s = (raw or "").strip()
    if not s:
        return ""
    if not s.startswith("{"):
        return s
    try:
        data = json.loads(s)
    except json.JSONDecodeError:
        return s
    if not isinstance(data, dict):
        return s
    msg = data.get("message")
    if isinstance(msg, dict) and "content" in msg:
        return str(msg.get("content") or "").strip()
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        m = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(m, dict) and "content" in m:
            return str(m.get("content") or "").strip()
    c = data.get("content")
    if isinstance(c, str):
        return c.strip()
    return s


def _full_response_for_review(raw: str) -> str:
    """results/review 로그에는 원문 보존을 우선한다."""
    return (raw or "").strip()


def _write_review_log(final_state: dict, out_dir: Path, stem_suffix: str) -> Path:
    """요청 포맷: 공격성공 프롬프트/응답값/방어코드/방어 후 응답값을 한눈에 저장."""
    phase3 = final_state.get("phase3_result", {}) or {}
    phase4 = final_state.get("phase4_result", {}) or {}
    phase3_history = final_state.get("phase3_history") or []
    phase4_history = final_state.get("phase4_history") or []

    source_rows: list[dict] = []
    defense_refs: list[tuple[int, str]] = []
    if phase3_history:
        for idx, entry in enumerate(phase3_history, start=1):
            if not isinstance(entry, dict):
                continue
            attempt = int(entry.get("attempt") or idx)
            for row in entry.get("source_vulnerabilities") or []:
                if isinstance(row, dict):
                    source_rows.append({**row, "__attempt": attempt})
            for rel in entry.get("defense_json_files") or []:
                defense_refs.append((attempt, str(rel)))
    else:
        source_rows = list(phase3.get("source_vulnerabilities", []) or [])
        defense_refs = [(1, str(rel)) for rel in (phase3.get("defense_json_files", []) or [])]

    defense_map: dict[tuple[int, str], dict] = {}
    defense_map_fallback: dict[str, dict] = {}
    for attempt, rel in defense_refs:
        path = PROJECT_ROOT / rel
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            defense_id = str(payload.get("defense_id") or "")
            if defense_id:
                defense_map[(attempt, defense_id)] = payload
                defense_map_fallback[defense_id] = payload
        except Exception:
            continue

    phase4_map: dict[tuple[int, str], dict] = {}
    if phase4_history:
        for idx, entry in enumerate(phase4_history, start=1):
            if not isinstance(entry, dict):
                continue
            attempt = int(entry.get("attempt") or idx)
            for d in entry.get("details") or []:
                if not isinstance(d, dict):
                    continue
                defense_id = str(d.get("defense_id") or "")
                if defense_id:
                    phase4_map[(attempt, defense_id)] = d
    else:
        for d in phase4.get("details", []) or []:
            if isinstance(d, dict):
                defense_id = str(d.get("defense_id") or "")
                if defense_id:
                    phase4_map[(1, defense_id)] = d

    lines: list[str] = []
    p1_seed = (final_state.get("phase1_result") or {}).get("seed_mode")
    title = "phase3to4 review log" if p1_seed == "phase34_only" else "phase1to4 review log"
    lines.append(f"# {title} ({stem_suffix})")
    lines.append("")
    prov = final_state.get("smoke_llm_provenance")
    if isinstance(prov, dict):
        lines.append("## smoke_llm_provenance (Phase3 Blue / Ollama)")
        lines.append(f"- ollama_blue_target_model: {prov.get('ollama_blue_target_model')}")
        lines.append(f"- ollama_blue_model: {prov.get('ollama_blue_model')}")
        lines.append(f"- ollama_base_url: {prov.get('ollama_base_url')}")
        lines.append(f"- recorded_at: {prov.get('recorded_at')}")
        lines.append("")
    p2 = final_state.get("phase2_result", {}) or {}
    p2_results = [r for r in (p2.get("results", []) or []) if isinstance(r, dict)]
    p2_counter = Counter(str(r.get("judgment") or "") for r in p2_results)
    p2_vulnerable = int(p2_counter.get("vulnerable", 0))
    p1 = final_state.get("phase1_result", {}) or {}
    p1_vulnerable = int(p1.get("vulnerable_count") or 0)
    p1_safe = int(p1.get("safe_count") or 0)
    p1_ambiguous = int(p1.get("ambiguous_count") or 0)
    p1_error = int(p1.get("error_count") or 0)
    p3_generated = int(
        phase3.get("cumulative_defenses_generated", phase3.get("defenses_generated") or 0)
    )
    p3_failed = int(phase3.get("cumulative_failed", phase3.get("failed") or 0))
    pool_ids = _unique_defense_ids_from_phase3_seed(final_state)
    p3_unique = len(pool_ids)
    if p3_unique == 0:
        p3_unique = int(
            phase3.get("initial_total_vulnerabilities")
            or phase3.get("cumulative_total_vulnerabilities", p1_vulnerable + p2_vulnerable)
            or 0
        )
    p3_slots_sum = int(
        phase3.get(
            "cumulative_total_vulnerabilities",
            phase3.get("initial_total_vulnerabilities", p1_vulnerable + p2_vulnerable),
        )
        or 0
    )
    p3_total_handled = p3_generated + p3_failed
    lines.append(f"- phase4_to3_iteration: {final_state.get('iteration')}")
    lines.append(f"- phase1_total_scanned: {p1.get('total_scanned', 0)}")
    lines.append(f"- phase1_vulnerable: {p1_vulnerable}")
    lines.append(f"- phase1_safe: {p1_safe}")
    lines.append(f"- phase1_ambiguous: {p1_ambiguous}")
    lines.append(f"- phase1_error: {p1_error}")
    lines.append(f"- phase2_total_results: {len(p2_results)}")
    lines.append(f"- phase2_vulnerable: {p2_vulnerable}")
    lines.append(f"- phase2_safe: {int(p2_counter.get('safe', 0))}")
    lines.append(f"- phase2_ambiguous: {int(p2_counter.get('ambiguous', 0))}")
    lines.append(f"- phase2_error: {int(p2_counter.get('error', 0))}")
    lines.append(f"- phase2_generation_failed: {int(p2_counter.get('generation_failed', 0))}")
    lv = _last_phase4_verdict_by_defense_id(final_state)
    fs = sum(1 for did in pool_ids if lv.get(did) == "safe") if pool_ids else 0
    fu = sum(1 for did in pool_ids if lv.get(did) == "unsafe") if pool_ids else 0
    lines.append(f"- phase4_final_scorecard: 총 {p3_unique}건 중 safe {fs}건, unsafe {fu}건")
    lines.append(
        f"- phase3_blue_generation_slots_sum: {p3_slots_sum} "
        f"(Phase3→4 재시도 포함 Blue 처리 슬롯 합; 고유 취약 풀 {p3_unique}건과 다를 수 있음)"
    )
    lines.append(f"- phase3_defenses_generated: {p3_generated}")
    lines.append(f"- phase3_failed: {p3_failed}")
    lines.append(f"- phase3_total_handled: {p3_total_handled}")
    lines.append(f"- phase3_total_unhandled: {max(p3_slots_sum - p3_total_handled, 0)}")
    for fd in phase3.get("failed_details") or []:
        if isinstance(fd, dict):
            lines.append(
                f"  - phase3_fail: defense_id={fd.get('defense_id')} "
                f"category={fd.get('category') or '-'} error={fd.get('error')}"
            )
    lines.append(f"- phase4_total_tested_cumulative: {int(phase4.get('cumulative_total_tested', phase4.get('total_tested', 0)))}")
    lines.append(f"- phase4_safe_cumulative: {int(phase4.get('cumulative_safe', phase4.get('safe', 0)))}")
    lines.append(f"- phase4_unsafe_cumulative: {int(phase4.get('cumulative_unsafe', phase4.get('unsafe', 0)))}")
    lines.append(f"- phase4_total_tested_last_cycle: {int(phase4.get('total_tested', 0))}")
    lines.append(f"- phase4_safe_last_cycle: {int(phase4.get('safe', 0))}")
    lines.append(f"- phase4_unsafe_last_cycle: {int(phase4.get('unsafe', 0))}")
    lines.append(f"- phase4_passed_threshold_final: {bool(phase4.get('passed_threshold', False))}")
    if "benign_total" in phase4:
        lines.append(f"- phase4_benign_total: {phase4.get('benign_total', 0)}")
        lines.append(f"- phase4_false_positives: {phase4.get('false_positives', 0)}")
        lines.append(f"- phase4_benign_passed: {phase4.get('benign_passed', 0)}")
    lines.append("")

    if not source_rows:
        lines.append("## items")
        lines.append("- 기록할 취약점/방어 매핑 데이터가 없습니다.")
    else:
        for idx, row in enumerate(source_rows, start=1):
            defense_id = str(row.get("defense_id") or "")
            attempt = int(row.get("__attempt") or 1)
            defense_payload = defense_map.get(
                (attempt, defense_id),
                defense_map_fallback.get(defense_id, {}),
            )
            phase4_row = phase4_map.get((attempt, defense_id), {})

            lines.append(f"## item {idx} (defense_id={defense_id}, attempt={attempt})")
            lines.append("")
            lines.append(f"- category: {row.get('category') or ''}")
            lines.append(f"- subcategory: {row.get('subcategory') or ''}")
            lines.append(f"- phase: {row.get('phase')}")
            lines.append(f"- round: {row.get('round')}")
            lines.append(f"- judgment: {row.get('judgment')}")
            lines.append(f"- judgment_confidence: {row.get('judgment_confidence')}")
            lines.append(f"- failure_mode: {row.get('failure_mode') or ''}")
            lines.append(f"- mitre_technique_id: {row.get('mitre_technique_id') or ''}")
            lines.append("")
            original_attack_prompt = str(row.get("original_attack_prompt") or "").strip()
            round_input_prompt = str(row.get("round_input_prompt") or "").strip()
            transformed_attack_prompt = str(row.get("attack_prompt") or "").strip()
            if original_attack_prompt:
                lines.append("### 0) 원본 공격 프롬프트")
                lines.append(original_attack_prompt)
                lines.append("")
            if round_input_prompt and round_input_prompt != original_attack_prompt:
                lines.append("### 0.5) 변형 직전 입력 프롬프트")
                lines.append(round_input_prompt)
                lines.append("")
            lines.append("### 1) 공격성공 프롬프트")
            lines.append(transformed_attack_prompt)
            lines.append("")
            lines.append("### 2) 응답 값")
            lines.append(_full_response_for_review(str(row.get("target_response") or "")))
            lines.append("")
            lines.append("### 2.5) 판정 상세")
            lines.append(str(row.get("detail") or ""))
            lines.append("")
            lines.append("### 3) 방어코드")
            fallback_payload = {
                "defended_response": row.get("defended_response", ""),
                "defense_rationale": row.get("defense_rationale", ""),
                "failure_mode": row.get("failure_mode", ""),
            }
            if defense_payload or fallback_payload.get("defended_response") or fallback_payload.get("defense_rationale"):
                lines.append("```json")
                lines.append(_defense_code_preview(defense_payload or fallback_payload))
                lines.append("```")
            else:
                lines.append("(방어코드 없음)")
            lines.append("")
            lines.append("### 4) 방어 후 응답 값")
            after_resp = phase4_row.get("response_after_defense")
            if after_resp in (None, ""):
                lines.append("(방어 후 응답 없음)")
            else:
                lines.append(_full_response_for_review(str(after_resp)))
            lines.append("")
            benign_checks = phase4_row.get("benign_checks") or []
            if benign_checks:
                lines.append("### 5) Benign 테스트 로그")
                for b_idx, check in enumerate(benign_checks, start=1):
                    if not isinstance(check, dict):
                        continue
                    lines.append(f"- benign {b_idx}")
                    lines.append(f"  - blocked: {bool(check.get('blocked', False))}")
                    lines.append(f"  - prompt: {str(check.get('prompt') or '')}")
                    resp_text = str(check.get("response") or "").strip()
                    lines.append(f"  - response: {resp_text if resp_text else '(empty)'}")
                    if check.get("error"):
                        lines.append(f"  - error: {str(check.get('error'))}")
                lines.append("")

    review_prefix = "phase3to4_review" if p1_seed == "phase34_only" else "phase1to4_review"
    out_path = out_dir / f"{review_prefix}_{stem_suffix}.md"
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


# ── 세션 사전 생성 ────────────────────────────────────────────────────────────

async def _ensure_test_session(session_id: str, target_url: str) -> None:
    """run_scan 단독 실행 시 test_results FK 에러를 막기 위해 세션 row를 선생성."""
    try:
        from backend.database import async_session
        from backend.models.test_session import TestSession
    except Exception as e:
        print(f"[WARN] [{_log_ts()}] skip test_session pre-create (import failed): {e}")
        return

    try:
        session_uuid = uuid.UUID(str(session_id))
    except ValueError:
        print(f"[WARN] [{_log_ts()}] skip test_session pre-create (invalid session_id): {session_id}")
        return

    try:
        async with async_session() as db:
            row = TestSession(
                id=session_uuid,
                target_api_url=target_url,
                project_name="Phase1to4 Smoke",
                status="running",
            )
            db.add(row)
            await db.commit()
    except Exception as e:
        print(f"[WARN] [{_log_ts()}] test_session pre-create failed: {e}")


# ── 메인 ──────────────────────────────────────────────────────────────────────

async def _main(args: argparse.Namespace) -> int:
    if args.phase34_only and not args.phase34_input_json:
        print("[ERROR] --phase34-only 사용 시 --phase34-input-json 경로가 필요합니다.", flush=True)
        return 2

    if args.verbose_trace:
        logging.basicConfig(
            level=logging.INFO,
            format="[%(levelname)s] [%(asctime)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("sentence_transformers").setLevel(logging.WARNING)

    # ── Ollama URL 런타임 재정의 (--ollama-url 또는 자동감지) ─────────────────
    if args.ollama_url:
        import os as _os
        _os.environ["OLLAMA_BASE_URL"] = args.ollama_url
        from backend.config import settings as _s
        _s.OLLAMA_BASE_URL = args.ollama_url
        print(f"[INFO] [{_log_ts()}] ollama_url={args.ollama_url} (명시적 지정)")
    else:
        from backend.config import settings as _s
        print(f"[INFO] [{_log_ts()}] ollama_url={_s.OLLAMA_BASE_URL} (자동감지)")

    session_id = args.session_id or str(uuid.uuid4())
    print(f"[INFO] [{_log_ts()}] session_id={session_id}")
    print(f"[INFO] [{_log_ts()}] target_url={args.target_url}")
    print(f"[INFO] [{_log_ts()}] target_provider={args.target_provider or 'AUTO/ENV'}")
    print(f"[INFO] [{_log_ts()}] target_model={args.target_model or 'ENV/DEFAULT'}")
    _btt, _bm = _blue_tags_from_env()
    print(
        f"[INFO] [{_log_ts()}] ollama_blue_target_model={_btt or 'ENV/DEFAULT'} "
        f"ollama_blue_model={_bm or 'ENV/DEFAULT'}",
        flush=True,
    )
    print(f"[INFO] [{_log_ts()}] category={args.category or 'ALL'}")
    print(f"[INFO] [{_log_ts()}] max_attacks={args.max_attacks if args.max_attacks is not None else 'ALL'}")
    print(f"[INFO] [{_log_ts()}] phase2_rounds={args.phase2_rounds if args.phase2_rounds is not None else 'DEFAULT'}")
    print(f"[INFO] [{_log_ts()}] llm_timeout={args.llm_timeout if args.llm_timeout is not None else 'NONE'}")
    print(f"[INFO] [{_log_ts()}] verbose_trace={'ON' if args.verbose_trace else 'OFF'}")
    if args.shuffle:
        print(f"[INFO] [{_log_ts()}] shuffle=ON (seed={args.seed})")
    else:
        print(f"[INFO] [{_log_ts()}] shuffle=OFF")

    if args.phase34_only:
        seed_path = Path(args.phase34_input_json)
        if not seed_path.is_absolute():
            seed_path = PROJECT_ROOT / seed_path
        print(f"[INFO] [{_log_ts()}] phase34_only=ON seed_json={seed_path}")
        print(f"[INFO] [{_log_ts()}] Phase3 -> 4 실행 시작 (Phase1~2 스킵)")
    else:
        print(f"[INFO] [{_log_ts()}] Phase1 -> 2 -> 3 -> 4 실행 시작")

    await _ensure_test_session(session_id, args.target_url)

    if args.phase34_only:
        seed_path = Path(args.phase34_input_json)
        if not seed_path.is_absolute():
            seed_path = PROJECT_ROOT / seed_path
        phase1_seed, phase2_seed = load_phase34_seed(seed_path)

        with _patched_llm_runtime(args.llm_timeout, verbose=args.verbose_trace):
            final_state = await run_scan_phase34(
                session_id=session_id,
                target_url=args.target_url,
                target_config={
                    "provider": args.target_provider,
                    "model": args.target_model,
                    "api_key": args.target_api_key,
                },
                phase1_result=phase1_seed,
                phase2_result=phase2_seed,
            )
    else:
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

    _inject_smoke_llm_provenance(final_state)
    summary = _short_summary(final_state)
    print(f"\n[INFO] [{_log_ts()}] === SUMMARY ===")
    sc = summary.get("phase4_final_scorecard") or ""
    if sc:
        print(f"[INFO] [{_log_ts()}] {sc}", flush=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    if args.save_full:
        out_dir = PROJECT_ROOT / "results"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem_suffix = _build_artifact_stem(ts, args)
        prefix = "phase3to4_smoke" if args.phase34_only else "phase1to4_smoke"
        out_path = out_dir / f"{prefix}_{stem_suffix}.json"
        out_path.write_text(
            json.dumps(final_state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n[INFO] [{_log_ts()}] full state saved: {out_path}")
        meta_path = out_dir / f"{prefix}_{stem_suffix}.run.meta.json"
        _write_run_meta(meta_path, args, out_path, stem_suffix)
        print(f"[INFO] [{_log_ts()}] run metadata saved: {meta_path}")
        review_path = _write_review_log(final_state, out_dir, stem_suffix)
        print(f"[INFO] [{_log_ts()}] review log saved: {review_path}")

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase1~4 통합 스모크 테스트")
    parser.add_argument(
        "--target-url",
        default="http://localhost:8010/chat",
        help="테스트 대상 챗봇 endpoint (기본: testbed /chat)",
    )
    parser.add_argument(
        "--target-provider",
        default=None,
        help=(
            "타겟 요청 형식. "
            "auto|docker_chatbot|generic|ollama_chat|ollama_generate|openai_chat"
        ),
    )
    parser.add_argument(
        "--target-model",
        default=None,
        help="타겟 provider가 model 필드를 요구할 때 사용할 모델명",
    )
    parser.add_argument(
        "--target-api-key",
        default=None,
        help="OpenAI 호환 타겟 등 Authorization Bearer 키가 필요한 경우 사용",
    )
    parser.add_argument(
        "--ollama-url",
        default=None,
        help="Ollama API base URL (예: http://localhost:11434). 미지정 시 OLLAMA_BASE_URL 환경변수 또는 자동감지",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="미지정 시 UUID 자동 생성",
    )
    parser.add_argument(
        "--save-full",
        action="store_true",
        help="최종 상태 JSON을 results/ 에 저장",
    )
    parser.add_argument(
        "--category",
        default=None,
        help="카테고리 필터 (예: LLM01). 미지정 시 전체",
    )
    parser.add_argument(
        "--max-attacks",
        type=int,
        default=None,
        help="Phase1 공격 수 제한 (예: 20). 미지정 시 전체",
    )
    parser.add_argument(
        "--phase2-rounds",
        type=int,
        default=None,
        help="Phase2 최대 라운드 임시 설정 (미지정 시 기본값 유지)",
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Phase1 공격 목록 셔플",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="셔플 시드 (예: 42). --shuffle과 함께 사용 권장",
    )
    parser.add_argument(
        "--llm-timeout",
        type=float,
        default=60.0,
        help="LLM 호출 타임아웃 초 (기본 60초)",
    )
    parser.add_argument(
        "--verbose-trace",
        action="store_true",
        help="단계/LLM/HTTP 상세 trace 로그 출력",
    )
    parser.add_argument(
        "--phase34-only",
        action="store_true",
        help="Phase1~2 생략, --phase34-input-json 시드로 Phase3~4만 실행",
    )
    parser.add_argument(
        "--phase34-input-json",
        default=None,
        help="Phase34 전용 시드 JSON (patterns 배열 또는 {patterns: [...]})",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main(parse_args())))
