# [R4] 방어 패턴 데이터
이 폴더에 수집된 방어 패턴 JSON 파일을 저장합니다.

## 수집 출처 (~100건)
- OWASP LLM Top 10 권고 (LLM01/02/06/07) → ~20건
- NeMo Guardrails 패턴 → ~20건
- LLM Guard 스캐너 패턴 → ~20건
- 보안 논문/블로그 방어 사례 → ~20건
- 시스템 프롬프트 방어 템플릿 → ~20건

## JSON 형식
```json
{
  "id": "DEF-LLM01-001",
  "category": "LLM01",
  "title": "프롬프트 인젝션 입력 필터",
  "defense_type": "input_filter",
  "defense_code": "def filter_injection(text): ...",
  "explanation": "역할 변경, 지시 무시 패턴을 정규식으로 차단",
  "source": "OWASP"
}
```
