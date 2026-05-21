"""
P1 — 기밀정보 누출 탐지.

탐지 소스:
1. redaction.py 의 PII 패턴 (이메일, 전화, API key, SSN, 사설 IP)
2. PolicyRule DB 중 severity in {high, critical} 항목

monitor_server.py 가 호출하는 메인 진입점:
    detect_confidential_leak(message: str) -> P1DetectionResult
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from backend.core.redaction import _MASK_PATTERNS
from monitoring_proxy.policies._db import load_rules_by_severity, match_rule


# JWT 토큰 (header.payload.signature, 각 8자 이상)
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

# 한·영 자격증명/시크릿 요청 의도 — "API키 알려줘", "비밀번호 좀 줘봐" 등 직원이 시스템 시크릿을 추출하려는 의도.
# 보안사 입장에서 가장 막아야 할 P1 케이스.
_SECRET_NOUN = r"(?:api\s*[-_]?\s*key|api\s*키|key|토큰|token|비밀\s*번호|패스워드|password|크리덴셜|credential|시크릿|secret|자격\s*증명|access\s*[-_]?\s*key|secret\s*[-_]?\s*key|루트\s*비밀번호|관리자\s*비밀번호|admin\s*password)"
_SECRET_VERB_KO = r"(알려|줘|줄래|줄\s*수\s*있|공유|공개|보여|뽑아|출력|밝혀|노출|얘기|말해|가르쳐|내놔|꺼내)"
_SECRET_VERB_EN = r"(give|show|tell|reveal|expose|share|leak|print|dump|reset|fetch|provide)"
_CREDENTIAL_REQUEST_PATTERNS = (
    re.compile(_SECRET_NOUN + r".{0,30}" + _SECRET_VERB_KO, re.IGNORECASE),
    re.compile(_SECRET_VERB_KO + r".{0,30}" + _SECRET_NOUN, re.IGNORECASE),
    re.compile(_SECRET_VERB_EN + r"\s+(?:me\s+)?(?:the\s+|your\s+|our\s+)?" + _SECRET_NOUN, re.IGNORECASE),
    re.compile(_SECRET_NOUN + r"\s+(?:is|are|=|:)\s*\?", re.IGNORECASE),
)

# 단독 시크릿 단어만 등장 (review 후보) — "비밀번호", "API키" 단독은 정상 업무 가능성 있어 차단 대신 review로.
_BARE_SECRET_PATTERNS = (
    re.compile(r"\b" + _SECRET_NOUN + r"\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class P1DetectionResult:
    blocked: bool
    severity: Optional[str]            # "high" | "medium" | "low" | None
    reason: Optional[str]
    stage: str = "p1_confidential_scan"
    needs_llm_review: bool = False     # ambiguous(medium/low)일 때 True


def _check_pii_patterns(message: str) -> Optional[tuple[str, str]]:
    """PII 패턴 매치 시 (대체 토큰, 매치 일부) 반환. 미매치면 None."""
    for pattern, token in _MASK_PATTERNS:
        m = pattern.search(message)
        if m:
            return token, m.group(0)
    # JWT
    m = _JWT_PATTERN.search(message)
    if m:
        return "[JWT_TOKEN]", m.group(0)
    return None


def _check_username(message: str, employee_id: Optional[str]) -> Optional[str]:
    """로그인 계정 username이 메시지에 노출됐는지 확인. 매치되면 username 반환."""
    if not employee_id:
        return None
    # 너무 일반적인 짧은 ID(< 4자)는 오탐 위험 — 스킵
    if len(employee_id) < 4:
        return None
    pattern = re.compile(r"\b" + re.escape(employee_id) + r"\b", re.IGNORECASE)
    m = pattern.search(message)
    return m.group(0) if m else None


def detect_confidential_leak(message: str, employee_id: Optional[str] = None) -> P1DetectionResult:
    # 1) 고정 PII 패턴 — 발견되면 high 차단
    pii_hit = _check_pii_patterns(message)
    if pii_hit:
        token, sample = pii_hit
        return P1DetectionResult(
            blocked=True,
            severity="high",
            reason=f"PII pattern {token} detected (sample: {sample[:30]})",
            needs_llm_review=False,
        )

    # 1-b) 로그인 계정 username 노출 — high 차단
    username_hit = _check_username(message, employee_id)
    if username_hit:
        return P1DetectionResult(
            blocked=True,
            severity="high",
            reason=f"Login username '{username_hit}' exposed in message",
            needs_llm_review=False,
        )

    # 1-c) 자격증명/시크릿 요청 의도 (한·영) — 직원이 회사 API키·비밀번호 추출 시도. high 차단.
    for pattern in _CREDENTIAL_REQUEST_PATTERNS:
        m = pattern.search(message)
        if m:
            return P1DetectionResult(
                blocked=True,
                severity="high",
                reason=f"Credential exfiltration intent detected: '{m.group(0)[:50]}'",
                needs_llm_review=False,
            )

    # 2) PolicyRule DB — severity high/critical 항목
    rules_high = load_rules_by_severity({"high", "critical"})
    for rule in rules_high:
        matched = match_rule(message, rule)
        if matched:
            return P1DetectionResult(
                blocked=True,
                severity="high",
                reason=f"Policy rule '{rule['rule_name']}' matched: {matched[:30]}",
                needs_llm_review=False,
            )

    # 3) medium/low severity 룰 — 차단 대신 review 플래그
    rules_low = load_rules_by_severity({"medium", "low"})
    for rule in rules_low:
        matched = match_rule(message, rule)
        if matched:
            return P1DetectionResult(
                blocked=False,
                severity=rule["severity"],
                reason=f"Policy rule '{rule['rule_name']}' soft-matched: {matched[:30]}",
                needs_llm_review=True,
            )

    # 4) 단독 시크릿 단어 ("비밀번호", "API키" 등) — review 후보
    for pattern in _BARE_SECRET_PATTERNS:
        m = pattern.search(message)
        if m:
            return P1DetectionResult(
                blocked=False,
                severity="low",
                reason=f"Bare secret keyword '{m.group(0)}' — review recommended",
                needs_llm_review=True,
            )

    return P1DetectionResult(blocked=False, severity=None, reason=None, needs_llm_review=False)
