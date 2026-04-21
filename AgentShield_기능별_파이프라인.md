# AgentShield 기능별 파이프라인

이 문서는 각 기능의 입력, 출력, 현재 상태, 다음 작업을 짧게 정리한 구현 기준 문서다.

## 1. Phase 1

### 목적

- seed 공격을 타겟에 대량 전송하고 1차 판정한다.

### 입력

- 공격 패턴 데이터
- `target_url`

### 출력

- `safe`, `vulnerable`, `ambiguous`, `error`

### 핵심 파일

- `backend/core/phase1_scanner.py`

### 현재 상태

- 동작함
- 기본 계약은 `messages -> content`
- 고객별 형식 변환은 아직 공통화되지 않음

## 2. Phase 2

### 목적

- safe 결과를 기반으로 Red Agent가 우회 변형을 만든다.

### 핵심 파일

- `backend/agents/red_agent.py`
- `backend/graph/run_pipeline.py`

### 현재 상태

- refusal subtype branching 반영
- harvest mode 반영
- success-anchor 반영

### 주의

- 런타임 prompt 효과는 `backend/agents/llm_client.py` 경유 구조와 함께 봐야 한다.

## 3. Judge

### 목적

- 규칙 기반 + guard LLM 기반 판정

### 핵심 파일

- `backend/core/judge.py`
- `backend/core/guard_judge.py`

### 현재 상태

- 비교 가능한 벤치마크 유지가 중요하다.
- 위생 점검은 side-channel로 추가하고, 판정 로직은 쉽게 흔들지 않는다.

## 4. Phase 3

### 목적

- 취약점에 맞는 방어 초안을 만든다.

### 현재 상태

- 설계는 잡혀 있으나 Phase 1/2에 비해 연결 완성도는 낮다.

## 5. Phase 4

### 목적

- Defense Proxy를 통과시켜 방어 효과와 오탐을 확인한다.

### 핵심 파일

- `backend/core/phase4_verify.py`
- `defense_proxy/proxy_server.py`

### 현재 상태

- 프록시 경유 재검증은 가능하다.
- 여기도 `messages -> content` 고정 계약을 직접 가정한다.

## 6. Monitoring Proxy

### 목적

- 직원 AI 사용 요청을 운영 게이트웨이에서 차단, 경고, 기록한다.

### 핵심 파일

- `monitoring_proxy/monitor_server.py`
- `monitoring_proxy/services/forwarder.py`

### 현재 상태

- 정책 흐름은 존재한다.
- outbound forwarder는 아직 placeholder 단계에서 막혀 있었다.
- develop 병합으로 testbed/QA 자산은 들어왔지만, 공통 adapter는 아직 없다.

## 7. Testbed

### 목적

- mock tool만 있는 환경이 아니라, 실제 DB/KB/Tool Gateway가 붙은 타겟 챗봇을 제공한다.

### 핵심 파일

- `testbed/target_chatbot/`
- `testbed/tool_gateway/`
- `database/testbed_schema.sql`

### 현재 상태

- develop 병합으로 기본 구조가 들어왔다.
- 팀 QA와 파이프라인 연결 기준을 이제 이 testbed 기준으로 맞춰야 한다.

## 8. API 레이어

### 목적

- 대시보드와 외부 호출이 Phase 1~4와 Monitoring을 실행하도록 연결한다.

### 핵심 파일

- `backend/api/scan.py`
- `backend/api/report.py`
- `backend/api/monitoring.py`

### 현재 상태

- 구조는 있으나 일부 엔드포인트는 아직 placeholder다.

## 9. 공통 설계 판단

### 지금 당장 맞춰야 하는 것

1. `target_url` 통합 방식
2. provider별 요청/응답 adapter
3. tool 이름 계약 유지
4. testbed를 기준으로 한 QA 절차 통일

### 지금 건드리면 안 되는 것

1. 비교 기준이 되는 judge 핵심 로직을 문서 없이 변경하는 것
2. tool 이름을 팀원별로 다르게 바꾸는 것
3. README와 실제 구현 상태를 다르게 적는 것
