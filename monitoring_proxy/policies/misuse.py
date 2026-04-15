from typing import Literal

from monitoring_proxy.schemas import PolicyResultSchema


class P2DetectionResult(PolicyResultSchema):
    category: Literal[
        "normal",
        "p2_toxic_or_harmful",
        "p2_non_work_related",
        "p2_competitor_related",
    ]


WORK_RELATED_ALLOWLIST: tuple[str, ...] = (
    "report",
    "summary",
    "meeting",
    "document",
    "analysis",
    "code",
    "debug",
    "api",
    "database",
    "sql",
    "service",
    "backend",
    "frontend",
    "project",
    "work",
    "client",
    "customer",
    "proposal",
    "회의",
    "요약",
    "문서",
    "보고서",
    "분석",
    "코드",
    "디버그",
    "개발",
    "업무",
    "프로젝트",
    "고객",
    "서비스",
    "데이터",
)
NON_WORK_RELATED_KEYWORDS: tuple[str, ...] = (
    "joke",
    "poem",
    "song lyrics",
    "movie recommendation",
    "tv show recommendation",
    "entertainment recommendation",
    "restaurant recommendation",
    "travel itinerary",
    "dating advice",
    "horoscope",
    "game cheat",
    "weekend plan",
    "농담",
    "시 써줘",
    "노래 가사",
    "영화 추천",
    "예능 추천",
    "드라마 추천",
    "맛집 추천",
    "여행 일정",
    "연애 상담",
    "운세",
    "게임 공략",
    "주말 계획",
)
TOXIC_OR_HARMFUL_KEYWORDS: tuple[str, ...] = (
    "make a bomb",
    "build a bomb",
    "how to kill",
    "kill someone",
    "harm someone",
    "hurt someone",
    "murder",
    "suicide note",
    "self-harm",
    "malware",
    "ransomware",
    "phishing email",
    "ddos attack",
    "hate speech",
    "폭탄 만드는 법",
    "사람 죽이는 법",
    "살인 방법",
    "자살 방법",
    "자해 방법",
    "악성코드",
    "랜섬웨어",
    "피싱 메일",
    "디도스 공격",
    "혐오 발언",
    "해치는 방법",
    "해치는 법",
    "누군가를 해치는 방법",
)
COMPETITOR_KEYWORDS: tuple[str, ...] = (
    "competitor",
    "rival company",
    "competitor product",
    "competitor weakness",
    "other company strategy",
    "steal market share",
    "benchmark competitor pricing",
    "삼성",
    "lg",
    "네이버",
    "카카오",
    "쿠팡",
    "경쟁사",
    "타사",
    "제품 약점",
    "제품 비교",
    "시장 점유율 빼앗기",
    "가격 전략",
)
COMPETITOR_INTENT_KEYWORDS: tuple[str, ...] = (
    "collect",
    "gather",
    "investigate",
    "research",
    "analyze",
    "scrape",
    "find out",
    "compare",
    "comparison table",
    "정리해줘",
    "조사해줘",
    "수집해줘",
    "분석해줘",
    "알아와",
    "크롤링",
    "비교표",
    "비교해줘",
    "만들어줘",
)


def detect_inappropriate_use(text: str) -> P2DetectionResult:
    lowered = text.strip().lower()

    for keyword in TOXIC_OR_HARMFUL_KEYWORDS:
        if keyword in lowered:
            return P2DetectionResult(
                category="p2_toxic_or_harmful",
                blocked=True,
                needs_llm_review=False,
                stage="p2_inappropriate_use",
                severity="high",
                reason=f"toxic content keyword detected: {keyword}",
            )

    competitor_hit = next(
        (keyword for keyword in COMPETITOR_KEYWORDS if keyword in lowered),
        None,
    )
    competitor_intent_hit = next(
        (keyword for keyword in COMPETITOR_INTENT_KEYWORDS if keyword in lowered),
        None,
    )
    if competitor_hit and competitor_intent_hit:
        return P2DetectionResult(
            category="p2_competitor_related",
            blocked=True,
            needs_llm_review=False,
            stage="p2_inappropriate_use",
            severity="medium",
            reason=(
                "competitor-related query detected: "
                f"{competitor_hit} + {competitor_intent_hit}"
            ),
        )

    allowlist_hit = next(
        (keyword for keyword in WORK_RELATED_ALLOWLIST if keyword in lowered),
        None,
    )
    non_work_hit = next(
        (keyword for keyword in NON_WORK_RELATED_KEYWORDS if keyword in lowered),
        None,
    )
    if non_work_hit and not allowlist_hit:
        return P2DetectionResult(
            category="p2_non_work_related",
            blocked=False,
            needs_llm_review=True,
            stage="p2_inappropriate_use",
            severity="low",
            reason=f"non-work-related request detected: {non_work_hit}",
        )

    return P2DetectionResult(
        category="normal",
        blocked=False,
        needs_llm_review=False,
        stage="p2_inappropriate_use",
        severity=None,
        reason=None,
    )
