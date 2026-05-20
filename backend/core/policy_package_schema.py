"""
Phase 5 policy package schemas.

These schemas describe the deterministic export artifact built from Phase4
verified defenses. LLM output is not trusted as policy directly.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


PolicyPackageStatus = Literal["validated", "invalid", "empty"]


class PackageManifest(BaseModel):
    schema_version: int = 1
    session_id: str
    generated_at: str
    source: str = "AgentShield Phase1-4"
    included_result_ids: list[int]
    excluded_result_ids: list[int]
    total_findings: int
    verified_safe_count: int
    package_status: PolicyPackageStatus


class VerifiedFinding(BaseModel):
    test_result_id: int
    category: Optional[str] = None
    severity: Optional[str] = None
    judgment: str
    verify_result: str
    # 자산 보존 원칙: 내부 export(JSON/DB/RAG)에는 항상 원문이 들어감.
    # 외부 공유용 PDF/ZIP을 만들 때만 별도 단계에서 마스킹된 사본을 생성한다.
    attack_prompt: str
    target_response: str
    defended_response: str
    defense_rationale: str
    mitre_technique_id: Optional[str] = None


class MaskingRule(BaseModel):
    id: str
    target: Literal["input", "output", "input_output"]
    pattern_family: Literal["api_key", "email", "phone", "ssn", "ip"]
    replacement: str
    enabled: bool = True


class RefusalTemplate(BaseModel):
    category: str
    template: str
    verified_result_id: int
    verified_by: Literal["phase4_judge"] = "phase4_judge"
    verify_result: Literal["safe"] = "safe"


class MiddlewarePolicy(BaseModel):
    version: int = 1
    input_policy: dict[str, bool]
    output_policy: dict[str, bool]
    category_actions: dict[str, str]
    # 산업 표준 권고 매핑(OWASP LLM Top 10 등) 기반의 기본 가이드라인.
    # 고객사 환경/미들웨어 스택에 맞춰 보안팀 리뷰 후 채택해야 함.
    source: str = "OWASP LLM Top 10 (v1.1) — default category-action mapping"
    advisory: str = (
        "이 정책은 OWASP LLM Top 10 일반 권고안 기반의 기본값입니다. "
        "고객사 미들웨어/SLM 스택에 맞춘 맞춤 조정과 보안팀 리뷰 후 운영 환경에 적용해야 합니다."
    )


class RegressionTestCase(BaseModel):
    test_id: str
    source_result_id: int
    category: Optional[str] = None
    # 자산 원문 — 우리 회귀 테스트로 다시 실행해야 하므로 마스킹하면 의미가 사라진다.
    attack_prompt: str
    expected_judgment_after_defense: Literal["safe"] = "safe"
    must_not_contain: list[str] = Field(default_factory=list)
    expected_action: str


class ValidationResult(BaseModel):
    valid: bool
    checks: dict[str, bool]
    errors: list[str] = Field(default_factory=list)


class PolicyPackageExportResult(BaseModel):
    ok: bool
    session_id: str
    package_dir: Optional[str] = None
    zip_path: Optional[str] = None
    download_url: Optional[str] = None
    validation: ValidationResult
