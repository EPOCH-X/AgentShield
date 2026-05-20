"""
Validation for Phase 5 policy package exports.
"""

from __future__ import annotations

import re
from typing import Iterable

from backend.core.policy_package_schema import (
    MaskingRule,
    RegressionTestCase,
    ValidationResult,
    VerifiedFinding,
)


RAW_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b(?:\+?82[-\s]?)?0?1[0-9][-\s]?\d{3,4}[-\s]?\d{4}\b"),
    re.compile(r"\b\d{6}-\d{7}\b"),
)

ALLOWED_PATTERN_FAMILIES = {"api_key", "email", "phone", "ssn", "ip"}


def contains_raw_secret(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in RAW_SECRET_PATTERNS)


def _all_no_raw_secret(findings: Iterable[VerifiedFinding]) -> bool:
    for finding in findings:
        if contains_raw_secret(finding.attack_prompt):
            return False
        if contains_raw_secret(finding.target_response):
            return False
        if contains_raw_secret(finding.defended_response):
            return False
    return True


def validate_policy_package(
    *,
    findings: list[VerifiedFinding],
    masking_rules: list[MaskingRule],
    regression_tests: list[RegressionTestCase],
    for_external: bool = False,
) -> ValidationResult:
    """
    for_external=False (기본): 내부 자산용 export. 원문 보존이 정상이므로 no_raw_secret은 정보용으로만 기록.
    for_external=True: 외부 공유 산출물(PDF/ZIP). raw secret 잔존 시 valid=False.
    """
    errors: list[str] = []
    included_ids = {item.test_result_id for item in findings}
    regression_ids = {item.source_result_id for item in regression_tests}

    no_raw_secret = _all_no_raw_secret(findings)
    checks = {
        "has_verified_findings": bool(findings),
        "only_verified_safe": all(item.judgment == "vulnerable" and item.verify_result == "safe" for item in findings),
        "no_raw_secret": no_raw_secret,
        "non_empty_defenses": all(bool(item.defended_response.strip()) for item in findings),
        "masking_rules_allowed": all(item.pattern_family in ALLOWED_PATTERN_FAMILIES for item in masking_rules),
        "regression_coverage": included_ids == regression_ids,
    }

    for key, ok in checks.items():
        if not ok:
            # 내부 export에서는 raw secret 잔존을 valid 실패 사유로 보지 않는다.
            if key == "no_raw_secret" and not for_external:
                continue
            errors.append(key)

    return ValidationResult(valid=not errors, checks=checks, errors=errors)

