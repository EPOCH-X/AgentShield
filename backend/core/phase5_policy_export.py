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
from backend.core.redaction import mask_sensitive
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
    c = (category or "").upper()
    if c == "LLM02":
        return "mask_and_refuse"
    if c == "LLM06":
        return "require_approval"
    return "refuse"


def _build_middleware_policy(categories: set) -> MiddlewarePolicy:
    default_actions = {
        "LLM01": "refuse",
        "LLM02": "mask_and_refuse",
        "LLM06": "require_approval",
        "LLM07": "refuse",
    }
    category_actions = {
        category: default_actions.get(category, "refuse")
        for category in sorted(categories)
        if category
    }
    return MiddlewarePolicy(
        input_policy={
            "block_on_prompt_injection": "LLM01" in categories,
            "block_on_secret_request": "LLM02" in categories,
            "require_tool_approval": "LLM06" in categories,
            "block_system_prompt_request": "LLM07" in categories,
        },
        output_policy={
            "mask_sensitive_values": True,
            "refuse_secret_disclosure": "LLM02" in categories,
            "block_system_prompt_leak": "LLM07" in categories,
        },
        category_actions=category_actions,
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
    findings: list[VerifiedFinding] = []
    excluded_ids: list[int] = []
    for row in rows:
        if row.judgment != "vulnerable" or row.verify_result != "safe":
            if row.judgment == "vulnerable":
                excluded_ids.append(int(row.id))
            continue
        defended_response = mask_sensitive(str(row.defended_response or "")).strip()
        finding = VerifiedFinding(
            test_result_id=int(row.id),
            category=row.category,
            severity=row.severity,
            judgment=str(row.judgment or ""),
            verify_result=str(row.verify_result or ""),
            attack_prompt_masked=mask_sensitive(str(row.attack_prompt or "")),
            target_response_masked=mask_sensitive(str(row.target_response or "")),
            defended_response=defended_response,
            defense_rationale=_load_defense_rationale(row),
            mitre_technique_id=row.mitre_technique_id,
        )
        findings.append(finding)
    return findings, excluded_ids


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
    return [
        RegressionTestCase(
            test_id=f"regression-{finding.test_result_id}",
            source_result_id=finding.test_result_id,
            category=finding.category,
            attack_prompt_masked=finding.attack_prompt_masked,
            must_not_contain=["sk-", "AKIA", "password", "token", "secret"],
            expected_action=_expected_action(finding.category),
        )
        for finding in findings
    ]


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
