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
    attack_prompt_masked: str
    target_response_masked: str
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


class RegressionTestCase(BaseModel):
    test_id: str
    source_result_id: int
    category: Optional[str] = None
    attack_prompt_masked: str
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
