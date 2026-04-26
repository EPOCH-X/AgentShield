#!/usr/bin/env python3
"""
Phase1~4 전체 그래프를 로컬에서 한 번 실행해보는 임시 스모크 스크립트.

사용:
  python scripts/run_phase1_to_4_smoke.py --target-url http://localhost:8010/chat
  python scripts/run_phase1_to_4_smoke.py --session-id smoke-001

테스트 후 삭제:
  rm scripts/run_phase1_to_4_smoke.py
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
import json
import random
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.graph.llm_security_graph import run_scan


def _log_ts() -> str:
    """로컬 시각(초). [INFO]/[TRACE]/[WARN] 공통."""
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def _trace(enabled: bool, msg: str) -> None:
    if enabled:
        print(f"[TRACE] [{_log_ts()}] {msg}", flush=True)


@contextmanager
def _patched_phase1_target_for_ollama(verbose: bool = True):
    """Phase1 기본 target 호출을 Ollama /api/chat 형식으로 맞춘다."""
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
        async def ollama_send_fn(client, prompt_text: str) -> str:
            _trace(verbose, f"phase1 target request start (prompt_len={len(prompt_text)})")
            resp = await client.post(
                target_url,
                json={
                    "model": settings.OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": prompt_text}],
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            # testbed /chat 응답({content: ...})와 Ollama 응답({message: {content: ...}}) 모두 허용
            content = str(data.get("message", {}).get("content", "")).strip()
            if not content:
                content = str(data.get("content", "")).strip()
            _trace(verbose, f"phase1 target request done (resp_len={len(content)})")
            return content

        effective_send_fn = send_fn or ollama_send_fn
        _trace(verbose, f"phase1 start (session_id={session_id}, category={category or 'ALL'})")
        result = await original_run_phase1(
            session_id=session_id,
            target_url=target_url,
            category=category,
            target_config=target_config,
            send_fn=effective_send_fn,
            llm=llm,
            on_result=on_result,
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
            # Phase2의 "타겟 모델 호출"만 변환하고, /api/generate(Agent LLM 호출)는 건드리지 않는다.
            if (
                normalized_url == normalized_target_url
                and isinstance(payload, dict)
                and "prompt" in payload
                and "messages" not in payload
            ):
                _trace(verbose, f"phase2 target payload convert (prompt_len={len(str(payload.get('prompt', '')))})")
                kwargs["json"] = {
                    "model": settings.OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": str(payload.get("prompt", ""))}],
                    "stream": False,
                }
            _trace(verbose, f"http post -> {url}")
            response = await super().post(url, *args, **kwargs)
            _trace(verbose, f"http post <- {url} status={response.status_code}")
            return response

    phase2_red_agent.httpx.AsyncClient = OllamaCompatibleAsyncClient
    try:
        yield
    finally:
        phase2_red_agent.httpx.AsyncClient = original_async_client


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

    async def wrapped_loader(requested_category: str | None = None) -> list[dict]:
        selected_category = category if category is not None else requested_category
        attacks = await original_loader(selected_category)
        if shuffle:
            rng = random.Random(seed)
            rng.shuffle(attacks)
        if max_attacks is not None and max_attacks >= 0:
            attacks = attacks[:max_attacks]
        return attacks

    phase1_scanner._load_attacks = wrapped_loader
    try:
        yield
    finally:
        phase1_scanner._load_attacks = original_loader


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
            result = await asyncio.wait_for(original_generate(self, *args, **kwargs), timeout=timeout_sec)
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


def _short_summary(final_state: dict) -> dict:
    p1 = final_state.get("phase1_result", {}) or {}
    p2 = final_state.get("phase2_result", {}) or {}
    p3 = final_state.get("phase3_result", {}) or {}
    p4 = final_state.get("phase4_result", {}) or {}

    return {
        "session_id": final_state.get("session_id"),
        "iteration": final_state.get("iteration"),
        "phase1_total_scanned": p1.get("total_scanned"),
        "phase1_vulnerable": len(p1.get("vulnerable_attacks", []) or []),
        "phase2_total_results": len(p2.get("results", []) or []),
        "phase2_vulnerable": len(
            [r for r in (p2.get("results", []) or []) if isinstance(r, dict) and r.get("judgment") == "vulnerable"]
        ),
        "phase3_defenses_generated": p3.get("defenses_generated"),
        "phase3_failed": p3.get("failed"),
        "phase4_total_tested": p4.get("total_tested"),
        "phase4_mitigated": p4.get("mitigated"),
        "phase4_bypassed": p4.get("bypassed"),
        "phase4_passed_threshold": p4.get("passed_threshold"),
    }


def _defense_code_preview(payload: dict) -> str:
    return json.dumps(
        {
            "defended_response": payload.get("defended_response", ""),
            "defense_rationale": payload.get("defense_rationale", ""),
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


def _write_review_log(final_state: dict, out_dir: Path, ts: str) -> Path:
    """요청 포맷: 공격성공 프롬프트/응답값/방어코드/방어 후 응답값을 한눈에 저장."""
    phase3 = final_state.get("phase3_result", {}) or {}
    phase4 = final_state.get("phase4_result", {}) or {}
    source_rows = phase3.get("source_vulnerabilities", []) or []
    defense_files = phase3.get("defense_json_files", []) or []
    phase4_details = phase4.get("details", []) or []

    defense_map: dict[str, dict] = {}
    for rel in defense_files:
        path = PROJECT_ROOT / str(rel)
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            defense_map[str(payload.get("defense_id") or "")] = payload
        except Exception:
            continue

    phase4_map = {str(d.get("defense_id") or ""): d for d in phase4_details if isinstance(d, dict)}

    lines: list[str] = []
    lines.append(f"# phase1to4 review log ({ts})")
    lines.append("")
    p2 = final_state.get("phase2_result", {}) or {}
    p2_vuln_n = len(
        [
            r
            for r in (p2.get("results", []) or [])
            if isinstance(r, dict) and r.get("judgment") == "vulnerable"
        ]
    )
    lines.append(f"- session_id: {final_state.get('session_id')}")
    lines.append(f"- phase2_vulnerable_count: {p2_vuln_n}")
    lines.append(f"- phase3_defenses_generated: {phase3.get('defenses_generated', 0)}")
    lines.append(f"- phase3_failed: {phase3.get('failed', 0)}")
    for fd in phase3.get("failed_details") or []:
        if isinstance(fd, dict):
            lines.append(
                f"  - phase3_fail: defense_id={fd.get('defense_id')} "
                f"category={fd.get('category') or '-'} error={fd.get('error')}"
            )
    lines.append(f"- phase4_total_tested: {phase4.get('total_tested', 0)}")
    lines.append(f"- phase4_mitigated: {phase4.get('mitigated', 0)}")
    lines.append(f"- phase4_bypassed: {phase4.get('bypassed', 0)}")
    lines.append(f"- phase4_passed_threshold: {bool(phase4.get('passed_threshold', False))}")
    lines.append("")

    if not source_rows:
        lines.append("## items")
        lines.append("- 기록할 취약점/방어 매핑 데이터가 없습니다.")
    else:
        for idx, row in enumerate(source_rows, start=1):
            defense_id = str(row.get("defense_id") or "")
            defense_payload = defense_map.get(defense_id, {})
            phase4_row = phase4_map.get(defense_id, {})

            lines.append(f"## item {idx} (defense_id={defense_id})")
            lines.append("")
            lines.append("### 1) 공격성공 프롬프트")
            lines.append(str(row.get("attack_prompt") or ""))
            lines.append("")
            lines.append("### 2) 응답 값")
            lines.append(_response_body_for_review(str(row.get("target_response") or "")))
            lines.append("")
            lines.append("### 3) 방어 산출물")
            if defense_payload:
                lines.append("```json")
                lines.append(_defense_code_preview(defense_payload))
                lines.append("```")
            else:
                lines.append("(방어 산출물 없음)")
            lines.append("")
            lines.append("### 3.5) 방어 응답(defended_response)")
            defended_response = str(row.get("defended_response") or "").strip()
            if defended_response:
                lines.append(_response_body_for_review(defended_response))
            else:
                lines.append("(방어 응답 없음)")
            lines.append("")
            lines.append("### 4) 방어 후 응답 값")
            after_resp = phase4_row.get("response_after_defense")
            if after_resp in (None, ""):
                lines.append("(방어 후 응답 없음)")
            else:
                lines.append(_response_body_for_review(str(after_resp)))
            lines.append("")
            lines.append("### 5) 재판정 결과")
            lines.append(f"- verdict: {str(phase4_row.get('verdict') or '(none)')}")
            if phase4_row.get("error"):
                lines.append(f"- error: {str(phase4_row.get('error'))}")
            lines.append("")

    out_path = out_dir / f"phase1to4_review_{ts}.md"
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


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


async def _main(args: argparse.Namespace) -> int:
    session_id = args.session_id or str(uuid.uuid4())
    print(f"[INFO] [{_log_ts()}] session_id={session_id}")
    print(f"[INFO] [{_log_ts()}] target_url={args.target_url}")
    print(f"[INFO] [{_log_ts()}] category={args.category or 'ALL'}")
    print(f"[INFO] [{_log_ts()}] max_attacks={args.max_attacks if args.max_attacks is not None else 'ALL'}")
    print(f"[INFO] [{_log_ts()}] phase2_rounds={args.phase2_rounds if args.phase2_rounds is not None else 'DEFAULT'}")
    print(f"[INFO] [{_log_ts()}] llm_timeout={args.llm_timeout if args.llm_timeout is not None else 'NONE'}")
    print(f"[INFO] [{_log_ts()}] verbose_trace={'ON' if args.verbose_trace else 'OFF'}")
    if args.shuffle:
        print(f"[INFO] [{_log_ts()}] shuffle=ON (seed={args.seed})")
    else:
        print(f"[INFO] [{_log_ts()}] shuffle=OFF")
    print(f"[INFO] [{_log_ts()}] Phase1 -> 2 -> 3 -> 4 실행 시작")
    await _ensure_test_session(session_id, args.target_url)

    with _patched_phase1_loader(
        category=args.category,
        max_attacks=args.max_attacks,
        shuffle=args.shuffle,
        seed=args.seed,
    ):
        with _patched_phase1_target_for_ollama(verbose=args.verbose_trace):
            with _patched_phase2_target_for_ollama(args.target_url, verbose=args.verbose_trace):
                with _patched_phase2_rounds(args.phase2_rounds):
                    with _patched_llm_runtime(args.llm_timeout, verbose=args.verbose_trace):
                        final_state = await run_scan(session_id=session_id, target_url=args.target_url)

    summary = _short_summary(final_state)
    print(f"\n[INFO] [{_log_ts()}] === SUMMARY ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    if args.save_full:
        out_dir = PROJECT_ROOT / "results"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"phase1to4_smoke_{ts}.json"
        out_path.write_text(json.dumps(final_state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\n[INFO] [{_log_ts()}] full state saved: {out_path}")
        review_path = _write_review_log(final_state, out_dir, ts)
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
        help="LLM 호출 타임아웃 초 (기본 60초, None 불가)",
    )
    parser.add_argument(
        "--verbose-trace",
        action="store_true",
        help="단계/LLM/HTTP 상세 trace 로그 출력",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main(parse_args())))
