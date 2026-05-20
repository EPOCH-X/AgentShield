"""
Phase 5 — verified policy package export.

Builds deterministic guardrail artifacts only from Phase4 safe defenses.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.policy_package_schema import (
    MaskingRule,
    MiddlewarePolicy,
    PackageManifest,
    PolicyPackageExportResult,
    RefusalTemplate,
    RegressionTestCase,
    ValidationResult,
    VerifiedFinding,
)
from backend.core.policy_package_validator import validate_policy_package
from backend.core.redaction import mask_for_external_share
from backend.core import owasp_guidance
from backend.models import TestResult, TestSession


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = PROJECT_ROOT / "data" / "policy_packages"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_defense_rationale(row: TestResult) -> str:
    raw = str(row.defense_code or "").strip()
    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
            return str(parsed.get("defense_rationale") or "").strip()
        except Exception:
            return ""
    return ""


def _expected_action(category: Optional[str]) -> str:
    return owasp_guidance.default_action(category)


def _build_middleware_policy(categories: set) -> MiddlewarePolicy:
    input_policy, output_policy = owasp_guidance.build_input_output_policy(categories)
    return MiddlewarePolicy(
        input_policy=input_policy,
        output_policy=output_policy,
        category_actions=owasp_guidance.build_category_action_map(categories),
        source=owasp_guidance.get_source() or "OWASP LLM Top 10",
    )


def _build_masking_rules() -> list[MaskingRule]:
    return [
        MaskingRule(id="mask_api_key", target="input_output", pattern_family="api_key", replacement="[API_KEY]"),
        MaskingRule(id="mask_email", target="input_output", pattern_family="email", replacement="[EMAIL]"),
        MaskingRule(id="mask_phone", target="input_output", pattern_family="phone", replacement="[PHONE]"),
        MaskingRule(id="mask_ssn", target="input_output", pattern_family="ssn", replacement="[SSN]"),
        MaskingRule(id="mask_ip", target="input_output", pattern_family="ip", replacement="[IP]"),
    ]


def _write_json(path: Path, payload: Any) -> None:
    if hasattr(payload, "model_dump"):
        data = payload.model_dump(mode="json")
    elif isinstance(payload, list):
        data = [item.model_dump(mode="json") if hasattr(item, "model_dump") else item for item in payload]
    else:
        data = payload
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


async def _load_session_results(db: AsyncSession, session_id: UUID) -> tuple:
    session = await db.scalar(select(TestSession).where(TestSession.id == session_id))
    if not session:
        return None, []
    rows = (
        await db.scalars(
            select(TestResult)
            .where(TestResult.session_id == session_id)
            .order_by(TestResult.id)
        )
    ).all()
    return session, list(rows)


def _build_verified_findings(rows: list[TestResult]) -> tuple[list[VerifiedFinding], list[int]]:
    """내부 자산용 — 원문 보존. DB / JSON / RAG 어디로 가도 원문이어야 함."""
    findings: list[VerifiedFinding] = []
    excluded_ids: list[int] = []
    for row in rows:
        if row.judgment != "vulnerable" or row.verify_result != "safe":
            if row.judgment == "vulnerable":
                excluded_ids.append(int(row.id))
            continue
        finding = VerifiedFinding(
            test_result_id=int(row.id),
            category=row.category,
            severity=row.severity,
            judgment=str(row.judgment or ""),
            verify_result=str(row.verify_result or ""),
            attack_prompt=str(row.attack_prompt or ""),
            target_response=str(row.target_response or ""),
            defended_response=str(row.defended_response or "").strip(),
            defense_rationale=_load_defense_rationale(row),
            mitre_technique_id=row.mitre_technique_id,
        )
        findings.append(finding)
    return findings, excluded_ids


def _redact_findings_for_external_share(findings: list[VerifiedFinding]) -> list[VerifiedFinding]:
    """외부 공유 산출물(PDF/외부 ZIP) 생성 시 사용. 원본 findings 변경 없이 마스킹된 복사본 반환."""
    redacted: list[VerifiedFinding] = []
    for f in findings:
        redacted.append(VerifiedFinding(
            test_result_id=f.test_result_id,
            category=f.category,
            severity=f.severity,
            judgment=f.judgment,
            verify_result=f.verify_result,
            attack_prompt=mask_for_external_share(f.attack_prompt),
            target_response=mask_for_external_share(f.target_response),
            defended_response=mask_for_external_share(f.defended_response),
            defense_rationale=f.defense_rationale,
            mitre_technique_id=f.mitre_technique_id,
        ))
    return redacted


def _build_refusal_templates(findings: list[VerifiedFinding]) -> list[RefusalTemplate]:
    by_category: dict[str, VerifiedFinding] = {}
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    for finding in findings:
        category = (finding.category or "UNKNOWN").upper()
        prev = by_category.get(category)
        if not prev:
            by_category[category] = finding
            continue
        if severity_rank.get((finding.severity or "").lower(), 0) >= severity_rank.get((prev.severity or "").lower(), 0):
            by_category[category] = finding
    return [
        RefusalTemplate(
            category=category,
            template=finding.defended_response,
            verified_result_id=finding.test_result_id,
        )
        for category, finding in sorted(by_category.items())
    ]


def _build_regression_tests(findings: list[VerifiedFinding]) -> list[RegressionTestCase]:
    """카테고리별 must_not_contain은 yaml 가이드(보안팀 관리)에서 읽어온다. 빈 리스트면 일반 시크릿 패턴 폴백."""
    fallback_terms = ["sk-", "AKIA", "password", "token", "secret"]
    cases: list[RegressionTestCase] = []
    for finding in findings:
        terms = owasp_guidance.must_not_contain(finding.category) or fallback_terms
        cases.append(
            RegressionTestCase(
                test_id=f"regression-{finding.test_result_id}",
                source_result_id=finding.test_result_id,
                category=finding.category,
                attack_prompt=finding.attack_prompt,
                must_not_contain=terms,
                expected_action=_expected_action(finding.category),
            )
        )
    return cases


async def export_policy_package(db: AsyncSession, session_id: str) -> PolicyPackageExportResult:
    sid = UUID(session_id)
    session, rows = await _load_session_results(db, sid)
    if not session:
        raise ValueError("session not found")

    findings, excluded_ids = _build_verified_findings(rows)
    masking_rules = _build_masking_rules()
    refusal_templates = _build_refusal_templates(findings)
    regression_tests = _build_regression_tests(findings)
    categories = {str(finding.category or "").upper() for finding in findings if finding.category}
    middleware_policy = _build_middleware_policy(categories)
    validation = validate_policy_package(
        findings=findings,
        masking_rules=masking_rules,
        regression_tests=regression_tests,
    )

    package_dir = PACKAGE_ROOT / session_id
    package_dir.mkdir(parents=True, exist_ok=True)

    manifest = PackageManifest(
        session_id=session_id,
        generated_at=_now_iso(),
        included_result_ids=[finding.test_result_id for finding in findings],
        excluded_result_ids=excluded_ids,
        total_findings=sum(1 for row in rows if row.judgment == "vulnerable"),
        verified_safe_count=len(findings),
        package_status="validated" if validation.valid else "empty" if not findings else "invalid",
    )

    _write_json(package_dir / "manifest.json", manifest)
    _write_json(package_dir / "verified_findings.json", findings)
    _write_json(package_dir / "masking_rules.json", masking_rules)
    _write_json(package_dir / "refusal_templates.json", refusal_templates)
    _write_json(package_dir / "middleware_policy.json", middleware_policy)
    _write_json(package_dir / "regression_tests.json", regression_tests)
    _write_json(package_dir / "validation_result.json", validation)
    (package_dir / "README.md").write_text(_build_readme(manifest, validation), encoding="utf-8")

    # 외부 공유 산출물 (HTML 항상, PDF는 weasyprint 있을 때) — 마스킹 사본 사용
    try:
        from backend.core import pdf_export
        redacted_findings = _redact_findings_for_external_share(findings)
        reports_dir = package_dir / "reports"
        report_outputs = pdf_export.export_reports(
            out_dir=reports_dir,
            session_id=session_id,
            manifest=manifest,
            findings=redacted_findings,
            regression_count=len(regression_tests),
        )
        _write_json(package_dir / "reports_manifest.json", report_outputs)
    except Exception:
        import logging
        logging.getLogger(__name__).exception("[phase5] external share report generation failed")

    zip_path: Optional[Path] = None
    if validation.valid:
        archive = shutil.make_archive(str(package_dir), "zip", root_dir=package_dir)
        zip_path = Path(archive)

    return PolicyPackageExportResult(
        ok=validation.valid,
        session_id=session_id,
        package_dir=str(package_dir.relative_to(PROJECT_ROOT)),
        zip_path=str(zip_path.relative_to(PROJECT_ROOT)) if zip_path else None,
        download_url=f"/api/v1/policy-export/{session_id}/download" if zip_path else None,
        validation=validation,
    )


def _build_readme(manifest: PackageManifest, validation: ValidationResult) -> str:
    return "\n".join(
        [
            "# AgentShield Guardrail Policy Package",
            "",
            f"- session_id: {manifest.session_id}",
            f"- generated_at: {manifest.generated_at}",
            f"- package_status: {manifest.package_status}",
            f"- validation_valid: {validation.valid}",
            "",
            "This package includes only findings that were judged vulnerable and then verified safe after Phase4 defense review.",
            "Raw secrets and direct identifiers are masked before export.",
            "",
            "Files:",
            "- manifest.json",
            "- verified_findings.json",
            "- masking_rules.json",
            "- refusal_templates.json",
            "- middleware_policy.json",
            "- regression_tests.json",
            "- validation_result.json",
            "",
        ]
    )
