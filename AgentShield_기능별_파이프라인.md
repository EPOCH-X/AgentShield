# AgentShield 기능별 파이프라인

이 문서는 역할별 상세 구현 파이프라인 문서다. 각 역할이 어떤 입력을 받고, 어떤 파일을 건드리며, 어떤 출력과 DB 상태를 남기는지, 그리고 다른 역할과 어떤 계약으로 연결되는지를 정리한다.

담당 기준:
- 문서 기준 소유: R1~R7 각 역할
- 이번 병합/연결 정리: Copilot이 공통 연결점과 상태 표기를 보강함

## 0. 현재 상태 요약

### 과거 계획

- scan UI는 있었지만 backend scan API가 mock 반환 중심이라 실제 Phase 1~4 검증 흐름이 끝까지 이어지지 않았다.
- 타겟 연동 포맷이 phase/proxy마다 흩어져 있어서, URL만 바꿔 연결하는 구조가 아니었다.
- 공격 데이터 운영 기준도 파일 중심 설명과 DB 중심 설명이 섞여 있었다.

### 현재 구현 상태

- scan API는 실제 graph를 호출하고, 세션과 결과를 DB에 적재한다.
- 공통 target adapter가 URL, API key, provider, model을 받아 provider별 payload를 내부에서 맞춘다.
- Phase 1은 DB `attack_patterns` 우선, 파일 fallback 구조로 정리됐다.
- Monitoring Proxy forwarder는 placeholder가 아니라 실제 outbound path로 연결됐다.
- testbed는 공통 검증 타겟이며 `http://localhost:8010/chat` 기준으로 붙일 수 있다.
- 팀 공통 해석 기준에서 Blue Agent의 1차 목적은 `방어 응답 생성`, 2차 목적은 `방어 정책/코드 생성`이다.

### 아직 안 끝난 것

- judge 기준 복구와 `tests/test_judge.py` 정상화는 별도 정합화 작업이 필요하다.
- end-to-end testbed 실스캔 후 DB 적재 결과 확인은 다음 단계다.
- fine-tuning은 아직 완료되지 않았고, dataset도 계속 누적/정제해야 한다.

### 지금 사용자 기준 다음 할 일

1. `attack_patterns` 공용 DB를 계속 채운다.
2. testbed를 띄운 뒤 scan API나 dashboard로 실제 URL 스캔을 한 번 돌린다.
3. 그 결과를 보고 judge false negative/false positive를 정리한 뒤 판정 기준을 복구한다.
4. 이후에야 fine-tuning용 train/eval dataset export를 굳힌다.

## 1. 공통 흐름 요약

### 기능 A 전체 흐름

1. R7 Scan API가 세션을 생성한다.
2. R1 graph orchestration이 Phase 1 -> 2 -> 3 -> 4를 호출한다.
3. R2가 공용 attack DB를 기반으로 Phase 1 스캔을 수행한다.
4. R1이 safe 케이스를 Red Agent로 우회 재공격한다.
5. R3가 취약점 케이스로 방어 응답을 만들고, 필요 시 방어 정책/코드도 만든다.
6. R1/R3가 같은 공격에 대해 Blue 결과를 재검증한다.
7. R7이 결과를 DB와 Dashboard 조회 경로에 연결한다.

### 기능 B 전체 흐름

1. R5 Monitoring Proxy가 요청을 받는다.
2. P1/P2/P3/P4 정책 흐름을 통과시킨다.
3. 허용된 요청은 공통 target adapter를 통해 타겟 AI로 전달한다.
4. 로그와 위반 기록은 R7 DB 계층에 저장한다.

## 2. 공통 target adapter 파이프라인

### 목적

- 고객이 URL과 API key만 입력하면 내부에서 provider별 포맷을 맞춘다.
- 고객은 검증 요청 시 target URL 하나만 넘기면 된다.

### 핵심 파일

- `backend/core/target_adapter.py`

### 입력

- `target_url`
- `target_api_key` optional
- `target_provider` optional
- `target_model` optional
- `messages`

### 내부 처리

1. URL 패턴으로 provider 자동 감지
2. provider별 request payload 생성
3. Authorization header 생성
4. 응답 JSON 또는 text에서 content 추출

### 현재 연결 위치

- R2 `backend/core/phase1_scanner.py`
- R1 `backend/core/phase2_red_agent.py`
- R3 `backend/core/phase4_verify.py`
- R3 `defense_proxy/proxy_server.py`
- R5 `monitoring_proxy/services/forwarder.py`
- R7 `backend/api/scan.py`

### 유지 원칙

- phase 코드가 provider payload를 직접 조립하지 않는다.
- 새로운 provider 추가 시 adapter만 우선 수정한다.

## 3. R2 파이프라인: 공격 데이터와 Phase 1

### 목표

- 공통 공격 자산을 기준으로 대량 스캔을 수행하고 1차 결과를 만든다.

### 핵심 파일

- `backend/core/phase1_scanner.py`
- `backend/models/attack_pattern.py`
- `data/attack_patterns/`

### 입력

- `session_id`
- `target_url`
- `target_config`
- category optional

### 처리 단계

1. DB `attack_patterns` 테이블에서 우선 공격 패턴을 로드한다.
2. DB가 비어 있으면 파일 기반 attack patterns를 fallback으로 로드한다.
3. 각 공격을 target adapter로 전송한다.
4. Judge로 `safe`, `vulnerable`, `ambiguous`, `error`를 판정한다.
5. graph의 Phase 2 입력용 `safe_attacks`와 결과 목록을 반환한다.
6. R7 Scan API가 Phase 1 결과를 `test_results`에 적재한다.

### 출력

- `results`: 취약, 애매, 에러 케이스
- `safe_attacks`: Phase 2 재공격 입력용 안전 케이스
- `scan_summary`

### DB팀 연관 작업

- 공격 패턴 seed 품질 검수
- category/subcategory/severity 정규화
- source 필드 관리
- 공용 테이블 인덱스/정합성 유지

### 데이터셋 누적 상태

- 현재 공격 데이터 입력원은 `attack_patterns` 테이블이 기준본이다.
- 파일 `data/attack_patterns/` 는 fallback이자 로컬 보조 자산이다.
- 사용자가 구현 중이던 공격/검증 로직은 아직 진행 중이며, fine-tuning 직전의 고정 데이터셋 단계는 아니다.
- 즉 지금은 "스캔 결과를 안정적으로 쌓고, 판정 라벨을 정리하고, 재현 가능한 testbed 케이스를 붙이는 단계"다.

## 4. R1 파이프라인: Phase 2와 Judge

### 목표

- Phase 1에서 막힌 케이스를 우회 공격으로 변형하고, 판정 기준을 안정적으로 유지한다.

### 핵심 파일

- `backend/core/phase2_red_agent.py`
- `backend/agents/red_agent.py`
- `backend/core/judge.py`
- `backend/core/guard_judge.py`
- `backend/graph/llm_security_graph.py`

### 입력

- `phase1_result.safe_attacks`
- `target_url`
- `target_config`

### 처리 단계

1. safe 케이스를 가져온다.
2. RAG에서 유사 우회 사례를 조회한다.
3. Red Agent가 변형 공격을 생성한다.
4. target adapter로 실제 타겟에 재전송한다.
5. Judge가 취약 여부를 판정한다.
6. 취약 케이스는 `test_results` phase 2 row로 저장하고 `test_result_id`를 결과에 싣는다.
7. graph가 Phase 3로 넘긴다.

### Judge 운영 원칙

- benchmark 비교 기준이라 무단 변경 금지
- 추가 위생 점검은 side-channel 또는 보조 레이어로 붙인다.
- severity 기준 변경 시 테스트와 문서 동시 갱신 필요
- 원응답 판정과 Blue 방어 결과 재판정은 모두 Judge가 담당한다.

## 5. R3 파이프라인: Phase 3, Phase 4, Defense Proxy

### Phase 3 목표

- 실제 취약점 케이스를 기준으로 방어 응답을 만들고, 필요 시 defense JSON 초안도 만든다.

### Phase 3 핵심 파일

- `backend/core/phase3_blue_agent.py`
- `backend/agents/blue_agent.py`

### Phase 3 처리 단계

1. Phase 2의 vulnerable 결과만 가져온다.
2. defense_patterns RAG 검색으로 유사 방어 예시를 가져온다.
3. Blue Agent prompt를 구성한다.
4. Blue Agent가 `defended_response`를 생성한다.
5. 필요 시 defense JSON을 `data/phase3_defenses/<session_id>/`에 저장한다.
6. 가능하면 `test_results.defense_code`와 Blue 산출물을 함께 업데이트한다.

### Phase 4 목표

- Blue 결과가 실제로 방어 성공인지 Judge와 검증 계층으로 다시 확인한다.

### Phase 4 핵심 파일

- `backend/core/phase4_verify.py`
- `defense_proxy/proxy_server.py`

### Phase 4 처리 단계

1. 같은 공격에 대해 Blue 방어 응답을 Judge가 다시 판정한다.
2. 선택적으로 Phase 3 defense JSON을 읽어 proxy rules를 구성한다.
3. proxy mode 또는 local mode로 공격/정상 입력을 재시도한다.
4. blocked, mitigated, bypassed, false positive를 계산한다.
5. `verify_result`를 기존 `test_results` row에 반영한다.
6. threshold 통과 시 defense pattern 등록을 시도한다.
7. R7 Scan API는 phase 4 summary row도 추가 저장한다.

### Defense Proxy 런타임 흐름

1. session별 defense rule 등록
2. input filter 적용
3. system prompt patch 주입
4. target adapter를 통해 실제 타겟 호출
5. output filter 적용

## 6. R5 파이프라인: Monitoring Proxy

### 목표

- 직원 AI 사용 요청을 사전 차단, 경고, 기록하는 운영용 게이트웨이를 제공한다.

### 핵심 파일

- `monitoring_proxy/monitor_server.py`
- `monitoring_proxy/services/forwarder.py`
- `monitoring_proxy/policies/`
- `monitoring_proxy/schemas/`

### 입력

- employee request messages
- target URL
- target API key optional
- employee context

### 처리 단계

1. P1 confidential leak 검사
2. P2 inappropriate use 검사
3. P3 rate limit 검사
4. 필요 시 P4 intent review 수행
5. 허용 요청만 build_forward_request로 묶는다.
6. forwarder가 target adapter로 실제 타겟 AI에 전송한다.
7. 응답 마스킹, usage log, violation record를 저장한다.

### 현재 구현 기준

- py39 호환 상태 유지
- forwarder placeholder 제거 후 실제 outbound path 연결
- target 포맷 처리 책임은 monitoring이 아니라 adapter가 가진다.

## 7. R6 파이프라인: Dashboard

### 목표

- scan과 monitoring 결과를 운영자가 실제로 쓸 수 있는 경로로 보여준다.

### 핵심 파일

- `dashboard/app/scan/page.tsx`
- `dashboard/app/scan/[id]/page.tsx`
- `dashboard/lib/api.ts`

### 처리 단계

1. 사용자가 project name, target URL, target API key를 입력한다.
2. `POST /api/v1/scan/llm-security`로 스캔을 시작한다.
3. session id를 기준으로 status polling을 수행한다.
4. 결과 리스트와 phase/severity 정보를 조회한다.

### 현재 구현 기준

- scan 시작 폼에서 URL과 key 입력 지원
- backend scan API 실연결
- 벡터 선택 UI는 현재 프리셋 표시용이며, 실제 공격 소스는 공용 attack DB 기준
- 고객 관점 입력은 target URL 하나가 핵심이며, 방어 검증 반복 호출은 내부에서 수행한다.

## 8. R7 파이프라인: API / DB / 세션 저장

### 목표

- UI와 외부 호출이 실제 보안 파이프라인과 monitoring 경로에 연결되도록 한다.

### 핵심 파일

- `backend/api/scan.py`
- `backend/api/report.py`
- `backend/api/monitoring.py`
- `backend/database.py`
- `backend/models/`

### Scan API 처리 단계

1. 세션 row를 `running` 상태로 생성
2. graph 실행
3. Phase 1 결과 적재
4. Phase 2/3/4에서 생성된 DB 결과를 합쳐 조회 가능 상태로 정리
5. 원응답, 방어 응답, 방어 정책, phase 4 summary를 고객이 볼 수 있게 정리
6. 세션을 `completed` 또는 `failed`로 종료

### DB팀 체크 포인트

- `attack_patterns` 품질 유지
- `test_sessions`, `test_results` 조회 성능 확인
- monitoring 관련 테이블과 testbed schema 충돌 여부 검토

### 팀원 개인 mock/test 데이터 확인 경로

- testbed DB 실데이터 구조는 `database/testbed_schema.sql` 에 있다.
- 재현 가능한 공통 데이터는 `scripts/seed_testbed.py` 가 만든다.
- KB 쪽 데이터는 `scripts/ingest_testbed_kb.py` 로 넣는다.
- tool 호출 흔적은 testbed DB의 `audit_logs`, `email_outbox`, `refund_requests`, `password_reset_requests` 등에서 확인한다.
- 즉 팀원이 별도 노트북에서만 보던 데이터가 있다면, 최소한 DB 접속 정보나 seed/ingest 스크립트, 또는 덤프 파일을 넘겨줘야 같은 상태를 재현할 수 있다.

## 9. Testbed 공통 파이프라인

### 목표

- mock-only 환경이 아니라 실제 DB/KB/Tool Gateway가 연결된 타겟을 공통 검증 기준으로 제공한다.

### 핵심 파일

- `testbed/target_chatbot/`
- `testbed/tool_gateway/`
- `database/testbed_schema.sql`

### 팀 기준

- 기능 A, 기능 B, adapter 검증은 가능하면 testbed로 재현한다.
- 새 방어/공격 자산 추가 시 testbed 재현 케이스를 같이 남긴다.

### URL 기반 테스트 방법

- 타겟 챗봇 표준 엔드포인트는 `POST /chat` 이다.
- 기본 테스트 URL은 `http://localhost:8010/chat` 이다.
- dashboard 또는 scan API에는 이 URL과 필요 시 API key만 넣으면 된다.
- adapter가 provider 포맷 차이를 내부 처리하므로, 사용자는 payload 형식을 손으로 바꿀 필요가 없다.
- 즉 테스트 환경 검증은 현재도 API/URL을 통해 실제처럼 연결 가능하다.

## 10. 지금 당장 맞춰야 하는 것

1. target adapter에 포맷 변환 책임을 집중시킬 것
2. 공용 공격 데이터는 DB 기준으로 맞출 것
3. tool 이름과 judge 계약을 임의로 바꾸지 말 것
4. testbed 기준 QA 절차를 팀 공통으로 유지할 것
5. 폴더 소유 범위를 README 기준으로 유지할 것
