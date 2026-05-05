"""
Phase 3 — Blue Agent 방어 응답/코드 생성 오케스트레이션
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
from pathlib import Path
from typing import Any, Optional

from backend.agents.blue_agent import BlueDefenseBundle, build_blue_prompt, parse_blue_response
from backend.core.redaction import mask_sensitive

logger = logging.getLogger(__name__)

# OWASP 카테고리별 권고문 기본값.
# data/owasp_guide.json이 없거나 파싱 실패하면 이 매핑을 사용한다.
DEFAULT_OWASP_RECOMMENDATIONS: dict[str, str] = {
    "LLM01": "Constrain model behavior, enforce strict output schemas, filter input/output, segregate untrusted content, and require human approval for high-risk actions.",
    "LLM02": "Apply strict data sanitization and redaction, enforce least-privilege data access, restrict runtime data sources, and maintain transparent retention and opt-out policies.",
    "LLM06": "Minimize tool surface, permissions, and autonomy; avoid open-ended tools; execute actions in user context; and require explicit approval for high-impact operations.",
    "LLM07": "Keep secrets out of system prompts, avoid relying on prompts for security control, enforce authorization outside the LLM, and apply deterministic external guardrails.",
}


def _phase3_defense_json_dir(project_root: Path, session_id: str) -> Path:
    """방어 생성 결과 JSON 저장 디렉터리: data/phase3_defenses/<session_id>/"""
    return project_root / "data" / "phase3_defenses" / str(session_id)


def _phase3_failure_raw_dir(project_root: Path, session_id: str) -> Path:
    """Blue 응답 파싱 실패 시 원문을 남기는 디렉터리: data/phase3_failures/<session_id>/"""
    return project_root / "data" / "phase3_failures" / str(session_id)


def _write_defense_json_file(
    out_dir: Path,
    *,
    defense_id: str,
    session_id: str,
    category: Optional[str],
    severity: Optional[str],
    phase: Optional[int],
    bundle: BlueDefenseBundle,
    metadata: Optional[dict[str, Any]] = None,
) -> Path:
    # 사람이 검토/재활용하기 쉽게 취약점 단위 JSON 아티팩트로 저장한다.
    out_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "schema_version": 2,
        "session_id": str(session_id),
        "defense_id": defense_id,
        "category": category,
        "severity": severity,
        "phase": phase,
        "defended_response": bundle.defended_response,
        "defense_rationale": bundle.defense_rationale,
    }
    if metadata:
        payload.update({key: value for key, value in metadata.items() if value not in (None, "")})
    safe_id = defense_id.replace("/", "_")
    path = out_dir / f"defense_{safe_id}.json"
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def _write_failure_raw_file(
    out_dir: Path,
    *,
    defense_id: str,
    raw: str,
) -> Path:
    """파싱 실패 원문을 후속 분석용 텍스트 파일로 저장."""
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_id = defense_id.replace("/", "_")
    path = out_dir / f"blue_raw_{safe_id}.txt"
    path.write_text(raw, encoding="utf-8")
    return path


def _sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


async def _maybe_await(value: Any) -> Any:
    """동기/비동기 호출 결과를 동일한 방식으로 처리하기 위한 헬퍼."""
    if inspect.isawaitable(value):
        return await value
    return value


def _load_owasp_recommendations(project_root: Path) -> dict[str, str]:
    """
    우선순위:
    1) data/owasp_guide.json의 recommendation 필드
    2) 코드 내 기본 매핑
    """
    owasp_path = project_root / "data" / "owasp_guide.json"
    if not owasp_path.exists():
        return DEFAULT_OWASP_RECOMMENDATIONS

    try:
        raw = json.loads(owasp_path.read_text(encoding="utf-8"))
    except Exception:
        return DEFAULT_OWASP_RECOMMENDATIONS

    recs: dict[str, str] = {}
    if isinstance(raw, dict):
        for category, value in raw.items():
            if isinstance(value, dict):
                recommendation = str(value.get("recommendation", "")).strip()
                if recommendation:
                    recs[str(category)] = recommendation
            elif isinstance(value, str) and value.strip():
                recs[str(category)] = value.strip()

    return recs or DEFAULT_OWASP_RECOMMENDATIONS


def _derive_defense_id(vuln: dict[str, Any], idx: int) -> str:
    """Phase3/Phase4 간 식별자를 동일하게 유지하기 위한 defense_id 생성 규칙."""
    row_phase = vuln.get("phase")
    if row_phase == 2:
        return str(vuln.get("test_result_id") or f"phase2-{idx}")

    # Phase1 취약점은 test_result_id가 없을 수 있으므로 category/subcategory 기반 fallback ID를 부여한다.
    fallback_cat = str(vuln.get("category") or "unknown").lower()
    fallback_subcat = str(vuln.get("subcategory") or "none").lower().replace("/", "_")
    return str(vuln.get("test_result_id") or f"phase1-{fallback_cat}-{fallback_subcat}-{idx}")


async def run_phase3(
    session_id: str,
    phase1_result=None,  # phase1 결과(dict). 내부에서 judgment=="vulnerable"인 항목만 사용
    phase2_result=None,  # phase2 결과(dict). 내부에서 judgment=="vulnerable"인 항목만 사용
    phase4_result=None,  # phase4 재진입 시 사용(unsafe 항목만 재생성)
) -> dict[str, Any]:
    """
    1) phase1_result + phase2_result의 vulnerable 결과를 합쳐 사용
    2) defense_patterns에서 유사 방어 예시 검색(RAG)
    3) Blue prompt 생성
    4) llm.generate(role='blue')
    5) 파싱 후 defense JSON 저장
    """
    from backend.agents.llm_client import AgentShieldLLM
    from backend.rag.chromadb_client import rag_client
    from backend.database import async_session
    from backend.models.test_result import TestResult

    llm = AgentShieldLLM()

    generated = 0  # 방어 JSON 생성 성공 개수
    failed = 0  # 생성 실패 개수
    json_files: list[str] = []  # 생성된 JSON 파일의 상대 경로 목록
    failed_ids: list[str] = []  # 실패한 test_result_id 목록
    failed_details: list[dict[str, str]] = []  # 실패 건별 요약 (리뷰/스크립트에서 바로 확인)
    source_vulnerabilities: list[dict[str, Any]] = []  # Phase4 검증용 원본 취약점 스냅샷
    db_updated = 0  # test_results 업데이트 성공 건수
    db_update_failed_ids: list[str] = []  # test_results 업데이트 실패 ID

    project_root = Path(__file__).resolve().parents[2]  # 프로젝트 루트 경로
    defense_out_dir = _phase3_defense_json_dir(project_root, session_id)  # 세션별 출력 디렉터리
    failure_raw_dir = _phase3_failure_raw_dir(project_root, session_id)  # 파싱 실패 원문 저장 디렉터리
    owasp_recommendations = _load_owasp_recommendations(project_root)  # 카테고리별 권고문 매핑

    phase1_rows = (
        (phase1_result or {}).get("vulnerable_attacks", [])
        if isinstance(phase1_result, dict)
        else []
    )  # 원본 Phase1 취약점 목록
    phase2_rows = (
        (phase2_result or {}).get("results", [])
        if isinstance(phase2_result, dict)
        else []
    )  # 원본 Phase2 결과 목록

    phase1_vulns = [
        row
        for row in phase1_rows
        if isinstance(row, dict) and row.get("judgment") == "vulnerable"
    ]
    phase2_vulns = [
        row
        for row in phase2_rows
        if isinstance(row, dict) and row.get("judgment") == "vulnerable"
    ]
    vulns = phase1_vulns + phase2_vulns  # 취약점으로 판정된 항목만 Phase3 입력으로 사용

    # 재진입(phase4 -> phase3) 시에는 unsafe 항목만 재생성한다.
    retry_unsafe_ids: set[str] = set()
    if isinstance(phase4_result, dict):
        for item in phase4_result.get("details", []) or []:
            if isinstance(item, dict) and str(item.get("verdict") or "") == "unsafe":
                retry_unsafe_ids.add(str(item.get("defense_id") or ""))
        retry_unsafe_ids.discard("")

    if retry_unsafe_ids:
        filtered_vulns: list[dict[str, Any]] = []
        for idx, vuln in enumerate(vulns, start=1):
            if _derive_defense_id(vuln, idx) in retry_unsafe_ids:
                filtered_vulns.append(vuln)
        vulns = filtered_vulns

    total_vulns = len(vulns)
    if total_vulns:
        print(f"[phase3] start defenses: total={total_vulns}", flush=True)
    else:
        print("[phase3] no vulnerable cases to defend", flush=True)

    for idx, vuln in enumerate(vulns, start=1):
        defense_id = _derive_defense_id(vuln, idx)
        category = str(vuln.get("category") or "")  # OWASP 카테고리
        attack_prompt = str(vuln.get("attack_prompt") or "")  # 공격 프롬프트
        target_response = str(vuln.get("target_response") or "")  # 타겟 응답 원문
        failure_mode = str(vuln.get("failure_mode") or "").strip() or None
        mitre_technique_id = str(vuln.get("mitre_technique_id") or "").strip() or None
        judge_detail = str(vuln.get("detail") or "").strip()
        print(
            f"[phase3] [{idx}/{total_vulns}] defense_id={defense_id} category={category or 'unknown'} generating",
            flush=True,
        )

        rag_examples = ""  # defense_patterns에서 가져온 유사 방어 예시 텍스트
        try:
            # category/failure_mode/judge 근거를 함께 반영해 검색 질의를 구성한다.
            rag_query_parts = [
                category,
                failure_mode or "",
                attack_prompt[:160],
                judge_detail[:160],
                "defended response safe refusal",
            ]
            rag_query = " ".join(part for part in rag_query_parts if part).strip()
            rag_result = await _maybe_await(
                rag_client.search_defense(
                    query=rag_query,
                    n_results=3,
                    category=category or None,
                )
            )
            if isinstance(rag_result, dict) and "documents" in rag_result:
                docs = rag_result.get("documents", [])
                rag_rows = docs[0] if docs and isinstance(docs[0], list) else docs
                rag_sections = [str(x) for x in rag_rows if x]

                # metadata의 핵심 필드도 예시로 추가해 Blue 프롬프트에 함께 주입한다.
                metadatas = rag_result.get("metadatas", [])
                meta_rows = metadatas[0] if metadatas and isinstance(metadatas[0], list) else metadatas
                for meta in meta_rows or []:
                    if not isinstance(meta, dict):
                        continue
                    defended_example = str(meta.get("defended_response") or "").strip()
                    rationale_example = str(meta.get("defense_rationale") or "").strip()
                    defense_code_example = str(meta.get("defense_code") or "").strip()
                    verify_example = str(meta.get("verify_result") or "").strip()
                    failure_example = str(meta.get("failure_mode") or "").strip()

                    if not defended_example and defense_code_example.strip().startswith("{"):
                        try:
                            parsed_code = json.loads(defense_code_example)
                            defended_example = str(parsed_code.get("defended_response") or "").strip()
                            rationale_example = rationale_example or str(
                                parsed_code.get("defense_rationale") or ""
                            ).strip()
                        except Exception:
                            pass

                    meta_line = (
                        f"[verified_pattern] verify={verify_example}; "
                        f"failure_mode={failure_example}; "
                        f"defended_response={defended_example[:260]}; "
                        f"rationale={rationale_example[:220]}"
                    )
                    if defended_example or rationale_example:
                        rag_sections.append(meta_line)

                rag_examples = "\n".join(section for section in rag_sections if section)
        except Exception:
            rag_examples = ""

        owasp_recommendation = owasp_recommendations.get(category, "")
        prompt = build_blue_prompt(
            category=category,
            attack_prompt=attack_prompt,
            target_response=target_response,
            failure_mode=failure_mode,
            mitre_technique_id=mitre_technique_id,
            judge_detail=judge_detail,
            owasp_recommendation=owasp_recommendation,
            rag_defense_examples=rag_examples,
        )
        prompt_sha256 = _sha256_text(prompt)

        try:
            # Blue 모델의 응답은 구조화(JSON)로 강제하고, 파싱 실패 시 해당 건만 실패 처리
            raw = await _maybe_await(llm.generate(prompt, role="blue"))
            bundle = parse_blue_response(raw)
            blue_raw_failure_path = ""
            if bundle.parse_failed and isinstance(raw, str) and raw.strip():
                try:
                    blue_raw_failure_path = str(
                        _write_failure_raw_file(
                            failure_raw_dir,
                            defense_id=defense_id,
                            raw=raw,
                        ).relative_to(project_root)
                    )
                except Exception:
                    blue_raw_failure_path = ""
            bundle.defended_response = mask_sensitive(bundle.defended_response)
            defense_meta: dict[str, Any] = {
                "subcategory": vuln.get("subcategory"),
                "attack_prompt": attack_prompt,
                "target_response": target_response,
                "judge_reason": judge_detail,
                "failure_mode": failure_mode,
                "mitre_technique_id": mitre_technique_id,
                # 학습/리플레이 일치성을 위해, 실제 llm.generate() 입력 원문을 그대로 저장한다.
                "blue_input_prompt": prompt,
                "blue_input_prompt_sha256": prompt_sha256,
                "blue_input_prompt_parts": {
                    "judge_detail": judge_detail,
                    "owasp_recommendation": owasp_recommendation,
                    "rag_defense_examples": rag_examples,
                },
            }
            if bundle.parse_failed:
                defense_meta["blue_parse_failed"] = True
            if blue_raw_failure_path:
                defense_meta["blue_raw_response_file"] = blue_raw_failure_path
            written = _write_defense_json_file(
                defense_out_dir,
                defense_id=defense_id,
                session_id=session_id,
                category=category or None,
                severity=vuln.get("severity"),
                phase=vuln.get("phase"),
                bundle=bundle,
                metadata=defense_meta,
            )
            json_files.append(str(written.relative_to(project_root)))

            # R3 요구: 생성된 방어 응답/코드를 test_results에 반영 (검수 전 상태)
            try:
                async with async_session() as db:
                    row = None
                    if str(defense_id).isdigit():
                        row = await db.get(TestResult, int(defense_id))

                    if row:
                        row.defended_response = bundle.defended_response
                        row.defense_code = bundle.to_json_str()
                        if mitre_technique_id:
                            row.mitre_technique_id = mitre_technique_id
                        await db.commit()
                        db_updated += 1
                    else:
                        db_update_failed_ids.append(defense_id)
            except Exception:
                db_update_failed_ids.append(defense_id)

            source_vulnerabilities.append(
                {
                    "defense_id": defense_id,
                    "category": category,
                    "subcategory": vuln.get("subcategory"),
                    "phase": vuln.get("phase"),
                    "round": vuln.get("round"),
                    "original_attack_prompt": str(vuln.get("original_attack_prompt") or ""),
                    "round_input_prompt": str(vuln.get("round_input_prompt") or ""),
                    "attack_prompt": attack_prompt,
                    "target_response": target_response,
                    "defended_response": bundle.defended_response,
                    "judge_reason": judge_detail,
                    "detail": judge_detail,
                    "severity": vuln.get("severity"),
                    "judgment": vuln.get("judgment"),
                    "judgment_confidence": vuln.get("judgment_confidence"),
                    "failure_mode": failure_mode,
                    "mitre_technique_id": mitre_technique_id,
                    "blue_input_prompt": prompt,
                    "blue_input_prompt_sha256": prompt_sha256,
                    "blue_input_prompt_parts": {
                        "judge_detail": judge_detail,
                        "owasp_recommendation": owasp_recommendation,
                        "rag_defense_examples": rag_examples,
                    },
                }
            )
            generated += 1
            print(
                f"[phase3] [{idx}/{total_vulns}] done (generated={generated}, failed={failed})",
                flush=True,
            )
        except Exception as e:
            # 한 건 실패가 전체 실패로 이어지지 않도록 누적 후 다음 건 계속 처리.
            logger.exception(
                "Phase3 방어 생성 실패 (defense_id=%s, category=%s)",
                defense_id,
                category or "?",
            )
            raw_failure_path = ""
            raw_preview = ""
            if "raw" in locals() and isinstance(raw, str) and raw.strip():
                try:
                    written_raw = _write_failure_raw_file(
                        failure_raw_dir,
                        defense_id=defense_id,
                        raw=raw,
                    )
                    raw_failure_path = str(written_raw.relative_to(project_root))
                except Exception:
                    raw_failure_path = ""
                raw_preview = raw[:500].replace("\n", "\\n")
            failed += 1
            failed_ids.append(defense_id)
            failed_details.append(
                {
                    "defense_id": defense_id,
                    "category": category or "",
                    "error": str(e),
                    "blue_input_prompt": prompt,
                    "blue_input_prompt_sha256": prompt_sha256,
                    "blue_input_prompt_parts": {
                        "judge_detail": judge_detail,
                        "owasp_recommendation": owasp_recommendation,
                        "rag_defense_examples": rag_examples,
                    },
                    "raw_response_file": raw_failure_path,
                    "raw_response_preview": raw_preview,
                }
            )
            print(
                f"[phase3] [{idx}/{total_vulns}] failed (generated={generated}, failed={failed})",
                flush=True,
            )
            continue

    # ---- Phase3 요약 결과 반환 ----
    return {
        "session_id": session_id,
        "total_vulnerabilities": len(vulns),
        "defenses_generated": generated,
        "failed": failed,
        "failed_test_result_ids": failed_ids,
        "failed_details": failed_details,
        "defense_json_dir": str(defense_out_dir.relative_to(project_root)),
        "defense_json_files": json_files,
        "source_vulnerabilities": source_vulnerabilities,
        "db_updated": db_updated,
        "db_update_failed_ids": db_update_failed_ids,
        "owasp_recommendation_source": (
            "data/owasp_guide.json"
            if (project_root / "data" / "owasp_guide.json").exists()
            else "DEFAULT_OWASP_RECOMMENDATIONS"
        ),
    }
