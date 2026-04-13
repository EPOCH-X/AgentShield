"""
Phase 3 — Blue Agent 방어 코드 생성 오케스트레이션
"""

from __future__ import annotations

import json
from typing import Any

from backend.agents.blue_agent import build_blue_prompt, parse_blue_response


async def run_phase3(
    session_id: str,
    db,                  # SQLAlchemy Session (R7)
    llm,                 # AgentShieldLLM (R4)
    rag_client=None,     # optional: R4 Chroma client
) -> dict[str, Any]:
    """
    1) session의 vulnerable 결과 조회
    2) Blue prompt 생성
    3) llm.generate(role='blue')
    4) 파싱 후 defense_code 저장
    """
    # TODO: R7 ORM 모델 import로 교체
    from backend.models.test_result import TestResult

    vulns = (
        db.query(TestResult)
        .filter(
            TestResult.session_id == session_id,
            TestResult.judgment == "vulnerable",
        )
        .all()
    )

    generated = 0
    failed = 0

    for vuln in vulns:
        # 선택: RAG 참고 텍스트
        rag_text = ""
        if rag_client:
            try:
                # 팀 인터페이스 맞춰서 메서드명 조정 필요
                items = rag_client.search_defense(
                    query=f"{vuln.category} {vuln.attack_prompt[:100]} defense",
                    n=3,
                )
                rag_text = "\n".join(str(x) for x in items)
            except Exception:
                rag_text = ""

        prompt = build_blue_prompt(
            category=vuln.category,
            attack_prompt=vuln.attack_prompt or "",
            target_response=vuln.target_response or "",
            owasp_recommendation="",   # TODO: owasp guide 붙이면 채우기
            rag_defense_examples=rag_text,
        )

        try:
            raw = llm.generate(prompt, role="blue")
            bundle = parse_blue_response(raw)

            vuln.defense_code = bundle.to_json_str()
            vuln.defense_reviewed = False
            generated += 1
        except Exception:
            # 실패는 카운트하고 다음 취약점 진행
            failed += 1
            continue

    db.commit()

    return {
        "session_id": session_id,
        "total_vulnerabilities": len(vulns),
        "defenses_generated": generated,
        "failed": failed,
    }