"""
P1~P3 정책 탐지.

- P1 기밀유출: redaction.py PII 패턴 + PolicyRule DB(rule_type='keyword'|'regex', severity in {high,critical})
- P2 부적절사용: 고정 욕설/공격 키워드 + PolicyRule DB(severity in {medium,low})
- P3 Rate Limit: ENV 변수(MONITOR_RATE_DAILY/HOURLY/REPEAT) + 메모리 카운터

monitor_server.py가 사용하는 단일 진입점:
- detect_confidential_leak(message) -> P1DetectionResult
- detect_inappropriate_use(message) -> P2DetectionResult
- detect_rate_limit(employee_id, message) -> P3DetectionResult
- reset_rate_limit_state()  # 테스트 헬퍼
- DEFAULT_EMPLOYEE_ID
"""

from monitoring_proxy.policies.confidential import detect_confidential_leak, P1DetectionResult
from monitoring_proxy.policies.inappropriate import detect_inappropriate_use, P2DetectionResult
from monitoring_proxy.policies.rate_limit import detect_rate_limit, reset_rate_limit_state, P3DetectionResult


DEFAULT_EMPLOYEE_ID = "EMP-UNKNOWN"


__all__ = [
    "DEFAULT_EMPLOYEE_ID",
    "P1DetectionResult",
    "P2DetectionResult",
    "P3DetectionResult",
    "detect_confidential_leak",
    "detect_inappropriate_use",
    "detect_rate_limit",
    "reset_rate_limit_state",
]
