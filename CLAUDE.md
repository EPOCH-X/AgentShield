# AgentShield — Claude 작업 규칙

## 응답 언어
모든 응답은 한국어로 작성한다.

## 파일 수정 원칙
- 파일을 수정하거나 새로 생성하기 전에 반드시 먼저 브리핑한다.
  - 브리핑 형식: "어떤 파일에, 무엇을, 왜 바꾸는지"
- 사용자가 명시적으로 수정 요청을 하기 전까지는 코드를 보여주는 방식으로만 제안한다.
- 사용자가 허락하면 그때 Edit/Write 도구를 사용한다.

## R2 담당 파일 범위
아래 범위 외 파일을 수정하려 할 경우 반드시 먼저 경고한다.

**담당 범위:**
- `backend/core/phase1_scanner.py`
- `backend/models/attack_pattern.py`
- `data/attack_patterns/` (폴더 전체)
- `backend/data_cleaning/` (폴더 전체)

읽기(Read)는 어디든 가능. Edit/Write는 위 범위만 허락 후 진행.

## 공격 데이터 형식
`data/attack_patterns/*.json` 항목 필수 필드:
```json
{
  "prompt_text": "공격 프롬프트 텍스트",
  "intention": "공격 의도 설명",
  "category": "LLM01",
  "subcategory": "direct-injection",
  "severity": "High"
}
```

## Severity 기준 (3단계 고정, 첫 글자 대문자)
| 카테고리 | 서브카테고리 | severity |
|---------|------------|---------|
| LLM01 | 전체 | High |
| LLM02 | indirect-extraction | Medium |
| LLM02 | 나머지 | High |
| LLM06 | 전체 | Critical |
| LLM07 | constraint-mapping, indirect-extraction | Medium |
| LLM07 | 나머지 | High |

## Subcategory 허용값
- LLM01: direct-injection, indirect-injection, payload-splitting, obfuscation, code-injection, adversarial-suffix
- LLM02: pii-extraction, api-key-extraction, business-data-extraction, indirect-extraction, training-data-leakage
- LLM06: data-deletion, unauthorized-data-transfer, privilege-escalation, security-control-bypass, evidence-destruction
- LLM07: direct-extraction, indirect-extraction, roleplay-extraction, constraint-mapping, credential-extraction, obfuscated-extraction
