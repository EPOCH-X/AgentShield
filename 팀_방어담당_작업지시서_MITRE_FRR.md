# 방어담당 작업 지시서 — MITRE ATT&CK 매핑 & FRR 연동

> 작성일: 2026-04-23  
> 관련 브랜치: `EPOCH-12-AgentShield-red-agent-judge`  
> 담당: 방어(Blue Agent / Phase 3) 팀원

---

## 1. 배경 및 목적

CyberSecEval 4 (Meta PurpleLlama) 기준 정렬 작업으로 두 가지 기능이 추가됩니다.

| 기능 | 내용 |
|---|---|
| **MITRE ATT&CK 매핑** | 각 취약점 판정에 MITRE T-ID가 자동 첨부됨 |
| **FRR 측정** | 정상 요청을 투입해 오탐률(False Refusal Rate)을 세션마다 기록 |

백엔드(파이프라인·Judge·API)는 이미 구현 완료입니다. 방어팀이 해야 할 작업은 **Phase 3 방어 코드 생성 로직에 MITRE 컨텍스트를 활용하는 것**입니다.

---

## 2. 이미 완료된 작업 (건드리지 말 것)

| 파일 | 변경 내용 |
|---|---|
| `backend/core/mitre_mapping.py` | MITRE 매핑 딕셔너리 신규 생성 |
| `backend/core/frr_tracker.py` | FRR 추적 로직 신규 생성 |
| `backend/core/judge.py` | `full_judge()` 반환값에 `mitre_technique_id` 자동 첨부 |
| `backend/core/phase2_red_agent.py` | Phase 2 완료 후 FRR 배치 자동 실행 |
| `backend/api/scan.py` | `/api/v1/scan/mitre-mapping`, `/{session_id}/frr` 엔드포인트 추가 |
| `backend/models/test_result.py` | `mitre_technique_id` 컬럼 추가 |
| `backend/models/test_session.py` | `frr_total`, `frr_false_refusals`, `frr_rate` 컬럼 추가 |
| DB | 위 컬럼 마이그레이션 완료 |

---

## 3. 방어팀 작업 항목

### 3-1. Blue Agent 방어 코드 생성에 MITRE 컨텍스트 주입 (필수)

**파일**: `backend/agents/blue_agent.py`  
**목적**: 방어 코드 생성 시 MITRE 기법 정보를 프롬프트에 포함 → 더 정확한 방어 전략 생성

**수정 위치**: Blue Agent가 방어 프롬프트를 빌드하는 함수 내부

```python
# backend/agents/blue_agent.py 수정 예시

from backend.core.mitre_mapping import get_mitre_mapping

def build_blue_prompt(
    category: str,
    attack_prompt: str,
    target_response: str,
    failure_mode: str | None = None,
    mitre_technique_id: str | None = None,   # ← 새 파라미터 추가
    **kwargs,
) -> str:
    # 기존 프롬프트 빌드 코드 ...
    
    # MITRE 컨텍스트 추가
    mitre_ctx = ""
    if mitre_technique_id or failure_mode:
        mapping = get_mitre_mapping(category, failure_mode)
        primary = mapping["primary"]
        mitre_ctx = f"""
## MITRE ATT&CK Context
- Technique: {primary['technique_id']} — {primary['name']}
- Tactic: {primary['tactic']}
- Reference: {primary['url']}

방어 코드는 위 ATT&CK 기법의 완화(Mitigation) 전략을 반영해야 합니다.
"""
    
    # 기존 프롬프트에 mitre_ctx 삽입
    return existing_prompt + mitre_ctx
```

**호출부 수정**: Phase 3 파이프라인에서 `full_judge()` 결과의 `mitre_technique_id`를 `build_blue_prompt()`에 전달

```python
# backend/graph/run_pipeline.py 또는 Phase 3 실행 코드에서
verdict = await full_judge(category, attack_prompt, response)
mitre_id = verdict.get("mitre_technique_id")
failure_mode = verdict.get("failure_mode")

defense_prompt = build_blue_prompt(
    category=category,
    attack_prompt=attack_prompt,
    target_response=response,
    failure_mode=failure_mode,
    mitre_technique_id=mitre_id,   # ← 여기에 전달
)
```

---

### 3-2. Phase 3 결과 저장 시 MITRE ID 포함 (필수)

**파일**: Phase 3 결과를 DB에 저장하는 코드 (run_pipeline.py 또는 scan.py 내)

```python
# test_results 저장 시 mitre_technique_id 추가
TestResult(
    ...
    mitre_technique_id=verdict.get("mitre_technique_id"),  # ← 추가
)
```

---

### 3-3. Phase 3 verify_result에 FRR 고려 사항 (선택)

FRR 측정은 Phase 2 완료 후 자동 실행됩니다. 방어팀은 별도 FRR 코드를 작성할 필요 없습니다.

단, Phase 3 검증(`verify_result: blocked/mitigated/bypassed`) 시:
- 정상 요청(`is_legitimate_request=True`)에 대한 검증은 FRR 통계에 영향을 주지 않음
- 공격 프롬프트에 대한 검증만 `verify_result`에 기록

---

## 4. MITRE 매핑 참조 방법

```python
from backend.core.mitre_mapping import get_mitre_mapping, get_primary_technique_id

# 카테고리 대표 기법
technique_id = get_primary_technique_id("LLM01")
# → "T1190"

# failure_mode 세분화
technique_id = get_primary_technique_id("LLM01", "obfuscation_bypass")
# → "T1027"

# 전체 매핑 (primary + secondary + notes)
mapping = get_mitre_mapping("LLM06", "unauthorized_action")
primary = mapping["primary"]
# → {"technique_id": "T1106", "name": "Native API", "tactic": "Execution", ...}
```

---

## 5. LLM 카테고리 ↔ MITRE 매핑 요약표

| LLM 카테고리 | 대표 MITRE 기법 | 전술(Tactic) |
|---|---|---|
| LLM01: Prompt Injection | T1190 Exploit Public-Facing Application | Initial Access |
| LLM01: Obfuscation Bypass | T1027 Obfuscated Files or Information | Defense Evasion |
| LLM01: Multimodal Leak | T1566.001 Spearphishing Attachment | Initial Access |
| LLM02: Sensitive Info Disclosure | T1552.001 Credentials In Files | Credential Access |
| LLM02: PII Exfiltration | T1589 Gather Victim Identity Information | Reconnaissance |
| LLM06: Excessive Agency | T1106 Native API | Execution |
| LLM06: Privilege Escalation | T1078 Valid Accounts | Privilege Escalation |
| LLM06: Resource Exhaustion | T1499 Endpoint Denial of Service | Impact |
| LLM07: System Prompt Leak | T1592 Gather Victim Host Information | Reconnaissance |

전체 매핑: `backend/core/mitre_mapping.py` 참조

---

## 6. 테스트 방법

```bash
# 1. MITRE 매핑 API 테스트
curl -s http://localhost:8000/api/v1/scan/mitre-mapping | python3 -m json.tool | head -40

# 2. DB에 MITRE ID가 저장되는지 확인 (파이프라인 실행 후)
psql postgresql://agentshield:agentshield@localhost:5432/agentshield \
  -c "SELECT category, mitre_technique_id, count(*) 
      FROM test_results 
      WHERE mitre_technique_id IS NOT NULL 
      GROUP BY category, mitre_technique_id;"

# 3. FRR 통계 확인
SESSION_ID="<최신 세션 ID>"
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/scan/$SESSION_ID/frr | python3 -m json.tool
```

---

## 7. 완료 기준 체크리스트

- [ ] `build_blue_prompt()`에 `mitre_technique_id` 파라미터 추가 및 프롬프트 반영
- [ ] Phase 3 파이프라인에서 `mitre_technique_id`를 `build_blue_prompt()`에 전달
- [ ] Phase 3 결과 저장 시 `mitre_technique_id` 컬럼 포함
- [ ] 파이프라인 실행 후 `test_results.mitre_technique_id` 컬럼에 값이 들어오는지 DB 확인
- [ ] 브랜치 `EPOCH-12`에 커밋 후 PR 요청
