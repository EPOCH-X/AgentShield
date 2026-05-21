"""
P2 — 부적절 사용 탐지 (욕설/공격적 의도/우회 시도).

탐지 소스:
1. 고정 키워드 (욕설·해킹·우회 패턴)
2. PolicyRule DB 중 severity in {medium, low} & rule_name이 P1에서 안 잡힌 것

monitor_server.py 호출:
    detect_inappropriate_use(message: str) -> P2DetectionResult
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from monitoring_proxy.policies._db import load_rules_by_severity, match_rule


@dataclass(frozen=True)
class P2DetectionResult:
    blocked: bool
    severity: Optional[str]
    reason: Optional[str]
    category: str = "normal"  # "normal" | "p2_toxic_or_harmful" | "p2_policy_warning"
    stage: str = "p2_inappropriate_use"
    needs_llm_review: bool = False


# 고정 패턴 — 즉시 차단
_HARD_BLOCK_PATTERNS = (
    # 영문 공격성/우회
    re.compile(r"\b(how\s+to\s+(?:hack|exploit|bypass|jailbreak|crack))\b", re.IGNORECASE),
    re.compile(r"\bignore\s+(previous|prior|all)\s+(instructions?|rules?)\b", re.IGNORECASE),
    re.compile(r"\b(developer\s+mode|dan\s+mode|root\s+access)\b", re.IGNORECASE),
    re.compile(r"\b(?:fuck|shit|bitch|asshole)\b", re.IGNORECASE),
    # 한국어
    re.compile(r"(시발|씨발|개새끼|병신|좆같)"),
    re.compile(r"(이전\s*지시\s*무시|이전\s*규칙\s*무시|관리자처럼\s*행동)"),
)

# 소프트 패턴 — needs_llm_review만 True, 차단 아님
_SOFT_REVIEW_PATTERNS = (
    re.compile(r"\b(prompt\s+injection|reverse\s+engineer)\b", re.IGNORECASE),
    re.compile(r"(우회\s*방법|뚫는\s*방법|탈옥)"),
)


def detect_inappropriate_use(message: str) -> P2DetectionResult:
    # 1) 고정 hard block
    for pattern in _HARD_BLOCK_PATTERNS:
        m = pattern.search(message)
        if m:
            return P2DetectionResult(
                blocked=True,
                severity="medium",
                reason=f"Inappropriate use pattern matched: {m.group(0)[:30]}",
                category="p2_toxic_or_harmful",
                needs_llm_review=False,
            )

    # 2) PolicyRule DB — medium/low 항목 중 차단 액션
    rules = load_rules_by_severity({"medium", "low"})
    for rule in rules:
        matched = match_rule(message, rule)
        if not matched:
            continue
        if rule.get("action") == "block":
            return P2DetectionResult(
                blocked=True,
                severity=rule["severity"],
                reason=f"Policy rule '{rule['rule_name']}' matched: {matched[:30]}",
                category="p2_policy_warning",
                needs_llm_review=False,
            )
        # warn/log → review 플래그
        return P2DetectionResult(
            blocked=False,
            severity=rule["severity"],
            reason=f"Policy rule '{rule['rule_name']}' soft-matched: {matched[:30]}",
            category="p2_policy_warning",
            needs_llm_review=True,
        )

    # 3) soft review 패턴
    for pattern in _SOFT_REVIEW_PATTERNS:
        m = pattern.search(message)
        if m:
            return P2DetectionResult(
                blocked=False,
                severity="low",
                reason=f"Review-needed pattern: {m.group(0)[:30]}",
                category="p2_policy_warning",
                needs_llm_review=True,
            )

    return P2DetectionResult(
        blocked=False, severity=None, reason=None, category="normal", needs_llm_review=False,
    )
