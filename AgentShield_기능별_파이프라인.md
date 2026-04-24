# AgentShield 기능별 파이프라인

이 문서는 팀원별 담당 범위와 실제 최종 기능 형태를 연결해 보는 문서다. 목적은 단순 설명이 아니라, `누가 무엇을 고치고`, `어디까지 책임지고`, `어떤 출력이 최종 형태인지`, `어떤 변경은 마음대로 하면 안 되는지`를 분명히 해서 팀 충돌을 줄이는 것이다.

## 1. 이 문서에서 먼저 맞춰야 할 기준

- 기능 A는 `고객 챗봇 검증 + 개선안 생성` 이다.
- 기능 B는 `직원 AI 사용 통제` 이다.
- testbed는 기능 A를 재현하기 위한 공통 공격 타깃이다.
- Blue Agent의 1차 산출물은 `방어 응답` 이다.
- 공용 공격 데이터 기준본은 PostgreSQL `attack_patterns` 테이블이다.
- 결과 DB는 원본 저장소이고, 학습 후보는 cleaned export 기준으로 본다.

추가로 반드시 구분해야 할 경계:

- 고객에게 보이는 화면: scan 시작, 상태, 결과 요약, 방어 응답 비교
- 내부 운영자가 쓰는 화면: review queue 수정, Chroma 삭제/재적재, defense 승인
- testbed는 기능 A 재현용 내부 타깃이지 기능 B의 본체가 아니다.
- 공용 PostgreSQL / 공용 Chroma는 기본 내장 상태가 아니라 R7 운영 설정이 있어야 한다.

## 2. 기능별 작업 흐름과 최종 형태

이 문서에서 기능 설명은 `처음 무엇을 만들기 시작했는지`, `개발 중 무엇을 계속 맞춰야 하는지`, `최종적으로 어떤 결과가 나와야 하는지`, `배포 전후로 무엇을 계속 점검해야 하는지`까지 한 번에 보여줘야 한다.

### 기능 A의 최종 형태

#### 기능 A에서 처음 만들기 시작한 것

- 고객 챗봇에 공격 프롬프트를 자동으로 보내는 스캔 경로
- 공격 성공 여부를 판정하는 Judge 경로
- 안전해 보이는 응답도 다시 깨보는 Red Agent 경로
- 취약 응답에 대해 더 안전한 대안을 만드는 Blue Agent 경로
- 결과를 세션 기준으로 저장하는 DB 경로

#### 기능 A에서 개발 중 계속 맞춰야 하는 것

- 공격 패턴 기준본, Judge 기준, graph 상태 구조가 서로 어긋나지 않게 유지한다.
- target URL 하나로 스캔이 시작되고 끝나도록 API 계약을 유지한다.
- Blue Agent 출력이 단순 설명문이 아니라 실제 비교 가능한 방어 응답이 되게 유지한다.
- 재검증은 반드시 같은 공격 기준으로 원응답과 방어 응답을 비교하게 유지한다.
- 결과 저장 형식은 보고서, 대시보드, 학습 후보 export가 같이 사용할 수 있게 유지한다.

기능 A는 고객이 `target_url` 과 필요 시 API key를 넣으면, 내부에서 공격, 판정, 우회 공격, 방어 응답 생성, 재검증, 결과 저장, 보고서 구성을 수행하는 흐름이다.

최종적으로 고객이 보게 되는 형태는 다음과 같다.

1. 어떤 공격이 들어갔는지
2. 타깃이 원래 어떻게 답했는지
3. Judge가 왜 취약하다고 봤는지
4. Blue Agent가 어떤 더 안전한 응답을 제안했는지
5. 그 방어 응답이 다시 검증에서 안전해졌는지

#### 기능 A에서 마지막까지 계속 해야 하는 점검

- 공격, 원응답, 판정, 방어 응답, 재판정이 한 세트로 빠짐없이 저장되는지 확인한다.
- scan API에서 시작한 세션이 graph, DB, report, dashboard까지 끊기지 않는지 확인한다.
- 고객 챗봇과 testbed 모두 같은 계약으로 붙을 수 있는지 확인한다.
- `manual_review_needed` 나 실패 케이스가 학습 후보에 잘못 섞이지 않는지 확인한다.

### 기능 B의 최종 형태

#### 기능 B에서 처음 만들기 시작한 것

- 직원 요청을 먼저 받는 프록시 진입점
- 정책 기준으로 요청을 검사하는 엔진
- 허용 요청만 실제 모델로 보내는 forwarding 경로
- 민감정보를 가리는 masking 경로
- usage log 와 violation 저장 경로

#### 기능 B에서 개발 중 계속 맞춰야 하는 것

- 정책 판정 기준과 violation 저장 형식이 어긋나지 않게 유지한다.
- adapter 계약을 따라 실제 AI 호출 포맷을 일관되게 유지한다.
- 허용, 차단, 마스킹 결과가 운영자가 추적 가능한 형태로 남게 유지한다.
- 기능 A용 공격 시나리오와 기능 B 운영 정책 시나리오를 섞지 않게 유지한다.

기능 B는 직원 요청이 들어왔을 때, 정책 엔진이 이를 검사하고, 허용 요청만 실제 AI로 전달하며, 응답을 마스킹하고 로그와 위반 기록을 저장하는 운영 게이트웨이다.

최종적으로 운영자가 보게 되는 형태는 다음과 같다.

1. 어떤 요청이 들어왔는지
2. 어떤 정책에 걸렸는지
3. 실제 전달됐는지 차단됐는지
4. 어떤 마스킹이 적용됐는지
5. 어떤 usage log / violation 이 남았는지

#### 기능 B에서 마지막까지 계속 해야 하는 점검

- 차단돼야 하는 요청이 실제로 전달되지 않는지 확인한다.
- 허용 요청은 정상 응답을 반환하면서도 로그가 누락되지 않는지 확인한다.
- violation 과 usage log 가 운영 DB 기준으로 일관되게 쌓이는지 확인한다.
- 정책 파일 수정 시 마스킹, forwarder, 저장 로직이 같이 맞는지 확인한다.

### testbed의 최종 형태

#### testbed에서 처음 만들기 시작한 것

- 실제 공격 대상 역할을 하는 target chatbot
- 챗봇이 호출할 DB/KB/API 도구 서버
- 고객, 주문, 티켓, 환불, 로그가 들어 있는 테스트 DB
- weak / strict 비교를 위한 보안 모드 분리

#### testbed에서 개발 중 계속 맞춰야 하는 것

- tool gateway가 mock 이 아니라 실제 DB/KB/API를 조회하도록 유지한다.
- target chatbot 과 tool gateway 계약이 바뀌면 같이 맞춘다.
- weak 는 취약점 재현, strict 는 방어 비교라는 용도를 유지한다.
- 기능 A 재현용 환경이라는 해석을 유지하고 기능 B 본체와 섞지 않는다.

testbed는 학습이 끝난 고객 운영 챗봇 제품이 아니라, DB/KB/도구가 붙은 공통 공격 타깃이다. weak 와 strict 두 모드가 있고, 같은 질문을 두 모드에 보내 보안 규칙 적용 전후 차이를 비교할 수 있어야 한다.

#### testbed에서 마지막까지 계속 해야 하는 점검

- 로컬 환경에서 DB 시드, KB 적재, tool gateway, target chatbot 이 재현 가능해야 한다.
- weak 와 strict 에 같은 질문을 넣었을 때 차이가 실제로 드러나는지 확인한다.
- AgentShield scan API 가 `http://localhost:8010/chat` 같은 target URL 기준으로 end-to-end 검증 가능한지 확인한다.

## 3. 파일 단위 담당 기준

### R1 담당 파일

- `backend/agents/red_agent.py`
- `backend/core/phase2_red_agent.py`
- `backend/core/judge.py`
- `backend/core/guard_judge.py`
- `backend/graph/llm_security_graph.py`
- `backend/graph/run_pipeline.py`

### R1 최종 책임

- safe 케이스를 우회 공격으로 재시도한다.
- Judge 기준을 유지하고, 무단 완화나 무단 강화가 없게 한다.
- graph 상태 구조를 통일한다.

### R1이 처음부터 끝까지 해야 하는 일

- 처음에는 safe 케이스를 다시 깨기 위한 Red Agent 흐름과 Judge 기준을 잡는다.
- 진행 중에는 공격 변형 품질, Judge 일관성, graph phase 전환 상태를 계속 맞춘다.
- 최종적으로는 기능 A에서 우회 공격과 재판정이 실제로 돌아가게 만든다.
- 배포 전후에는 Judge 기준 변경이 문서, 테스트, 보고서 해석에 모두 반영됐는지 계속 확인한다.

### R1 최종 산출물

- Phase 2 변형 공격 결과
- Judge 판정 결과
- Phase 전환 가능한 graph 상태

### R1이 충돌 없이 작업하려면

- Judge 기준 변경 시 반드시 문서와 테스트를 같이 갱신한다.
- target 포맷 처리 로직을 phase 코드에 직접 넣지 않는다.
- Blue 결과 재판정 로직은 Judge 계약과 분리해서 임의 수정하지 않는다.

### R2 담당 파일

- `backend/core/phase1_scanner.py`
- `backend/models/attack_pattern.py`
- `data/attack_patterns/`
- `backend/data_cleaning/`

### R2 최종 책임

- 공격 패턴 기준본을 관리한다.
- Phase 1 대량 스캔을 안정적으로 수행한다.
- 공격 카테고리, 심각도, 출처 정합성을 유지한다.
- 학습용 cleaned export 기준을 유지한다.

### R2가 처음부터 끝까지 해야 하는 일

- 처음에는 공격 패턴 seed, 스키마, 기본 카테고리 체계를 만든다.
- 진행 중에는 DB 기준본과 파일 자산, Phase 1 스캔 입력 형식을 계속 맞춘다.
- 최종적으로는 대량 스캔과 cleaned export 가 같은 기준으로 이어지게 만든다.
- 배포 전후에는 raw 결과와 cleaned 후보가 섞이지 않는지 계속 점검한다.

### R2 최종 산출물

- DB 기준 공격 패턴 자산
- Phase 1 결과와 safe_attacks
- 정제된 학습 후보 export

### R2가 충돌 없이 작업하려면

- 파일 자산은 보조 또는 fallback으로 보고, 공용 기준은 DB로 맞춘다.
- `manual_review_needed` 결과를 학습 후보에 바로 섞지 않는다.
- testbed 공격 재현 케이스와 attack_patterns 카테고리 체계를 어긋나게 만들지 않는다.

### R3 담당 파일

- `backend/core/phase3_blue_agent.py`
- `backend/agents/blue_agent.py`
- `backend/core/phase4_verify.py`
- `defense_proxy/proxy_server.py`
- `data/defense_patterns/`

### R3 최종 책임

- 취약 응답을 바탕으로 방어 응답을 만든다.
- 필요 시 방어 정책 또는 defense JSON 초안을 만든다.
- Judge와 Verify를 통해 방어가 실제로 더 안전한지 재확인한다.

### R3가 처음부터 끝까지 해야 하는 일

- 처음에는 취약 응답을 받아 더 안전한 대안을 생성하는 Blue Agent 흐름을 만든다.
- 진행 중에는 defense prompt, defense pattern, verify 입력 구조를 계속 맞춘다.
- 최종적으로는 원응답과 방어 응답이 한 결과 안에서 비교 가능하게 만든다.
- 배포 전후에는 Blue 출력이 설명문으로 무너지는지, verify 가 같은 공격 기준을 유지하는지 계속 확인한다.

### R3 최종 산출물

- `defended_response`
- 선택적 `defense_code` 또는 defense JSON
- `verify_result`

### R3가 충돌 없이 작업하려면

- Blue Agent를 방어 코드 생성기만으로 좁게 해석하지 않는다.
- Verify는 같은 공격을 다시 보내는 구조를 유지한다.
- Defense Proxy 규칙과 Judge 기준을 섞어버리지 않는다.

### R4 담당 파일

- `backend/agents/llm_client.py`
- `backend/rag/`
- `backend/finetuning/`
- `adapters/`
- `models/`

### R4 최종 책임

- 역할별 모델 호출 안정성을 유지한다.
- RAG 검색과 적재를 관리한다.
- 어댑터, LoRA, 파인튜닝 자산을 관리한다.

### R4가 처음부터 끝까지 해야 하는 일

- 처음에는 역할별 모델 호출 경로와 공통 client 구조를 정리한다.
- 진행 중에는 adapter, RAG ingest/search, 모델 교체 경로를 계속 맞춘다.
- 최종적으로는 Red, Blue, Judge, testbed 가 필요한 모델과 검색 자산을 안정적으로 쓰게 만든다.
- 배포 전후에는 모델 이름, 환경변수, 임베딩 경로, Chroma 적재 상태가 문서와 실제 실행이 맞는지 계속 확인한다.

### R4 최종 산출물

- 안정적인 역할별 모델 호출 경로
- RAG ingest/search 유틸리티
- 파인튜닝용 모델 자산

### R4가 충돌 없이 작업하려면

- 모델 교체와 역할별 모델 분리를 문서 없이 바꾸지 않는다.
- testbed KB ingest 경로와 Phase 2/3 검색 경로를 혼동하지 않는다.

### R5 담당 파일

- `monitoring_proxy/monitor_server.py`
- `monitoring_proxy/services/forwarder.py`
- `monitoring_proxy/services/logging_service.py`
- `monitoring_proxy/services/violation_service.py`
- `monitoring_proxy/services/masking.py`
- `monitoring_proxy/policies/`
- `monitoring_proxy/schemas/`

### R5 최종 책임

- 직원 요청을 정책 기준으로 검사한다.
- 허용 요청만 타깃 AI로 전달한다.
- 마스킹, usage log, violation 저장을 유지한다.

### R5가 처음부터 끝까지 해야 하는 일

- 처음에는 monitoring proxy 진입점과 정책 판정 흐름을 만든다.
- 진행 중에는 forwarder, masking, violation 저장 형식을 계속 맞춘다.
- 최종적으로는 운영 환경에서 직원 AI 요청을 통제하고 추적 가능하게 만든다.
- 배포 전후에는 정책 변경이 차단 결과, 로그, 마스킹에 모두 반영되는지 계속 확인한다.

### R5 최종 산출물

- policy verdict
- outbound forwarding 결과
- usage log / violation record

### R5가 충돌 없이 작업하려면

- target 포맷 처리를 monitoring 내부에서 직접 다시 만들지 않는다.
- 포워딩은 adapter 계약을 따른다.
- testbed tool 오남용 시나리오와 monitoring 정책 시나리오를 혼동하지 않는다.

### R6 담당 파일

- `dashboard/app/scan/page.tsx`
- `dashboard/app/scan/[id]/page.tsx`
- `dashboard/lib/api.ts`
- `dashboard/components/`

### R6 최종 책임

- scan 시작, 상태, 결과 조회 UI를 제공한다.
- 운영자가 이해 가능한 화면을 구성한다.
- backend API 계약 변경을 UI에 반영한다.
- review queue 수정과 Chroma 삭제/재적재 같은 운영 UI를 제공한다.

### R6가 처음부터 끝까지 해야 하는 일

- 처음에는 scan 시작 화면과 기본 결과 조회 화면을 만든다.
- 진행 중에는 세션 상태, 결과 상세, API 응답 구조 변화를 계속 반영한다.
- 최종적으로는 운영자가 공격, 판정, 방어 응답, 재검증 결과를 한눈에 비교할 수 있게 만든다.
- 배포 전후에는 mock 기준 화면이 아니라 실제 API 기준 화면으로 유지되는지 계속 확인한다.

### R6 최종 산출물

- scan 시작 / 상태 / 결과 조회 UI
- review queue 수동 검수 UI
- Chroma 성공사례 관리 UI

- scan 시작 화면
- 세션 상태 조회 화면
- 결과 상세 조회 화면

### R6가 충돌 없이 작업하려면

- mock 응답 구조에 맞춰 UI를 고정하지 않는다.
- 입력 기준은 `target_url` 과 필요 시 key 라는 점을 유지한다.

### R7 담당 파일

- `backend/api/scan.py`
- `backend/api/report.py`
- `backend/api/monitoring.py`
- `backend/database.py`
- `backend/models/`
- `database/schema.sql`
- `database/testbed_schema.sql`
- `testbed/target_chatbot/`
- `testbed/tool_gateway/`
- `docker-compose.testbed.yml`
- `scripts/testbed_local.sh`
- `scripts/setup_testbed_db.sh`
- `scripts/seed_testbed.py`
- `scripts/ingest_testbed_kb.py`

### R7 최종 책임

- API, DB, testbed, 공용 실행 경로를 안정적으로 유지한다.
- 팀이 같은 PostgreSQL / Chroma를 보도록 공용 운영 기준을 관리한다.
- 수동 검수와 재적재 워크플로가 끊기지 않게 유지한다.

### R7이 지금부터 우선 해야 하는 일

- 공용 `DATABASE_URL` 과 공용 Chroma 운영 방식 확정
- `.env.shared.example` 을 실배포값 기준으로 팀에 배포
- review / vector admin API 를 운영 경로에 포함
- 팀원이 로컬/공용 환경을 혼동하지 않도록 실행 절차 고정

- API 계약을 실제 보안 파이프라인과 연결한다.
- DB 테이블과 ORM 정합성을 유지한다.
- testbed를 팀 공통 검증 환경으로 유지한다.
- 보고서와 결과 조회 경로를 제공한다.

### R7이 처음부터 끝까지 해야 하는 일

- 처음에는 scan, monitoring, report API 와 DB 스키마 기본 뼈대를 만든다.
- 진행 중에는 파이프라인 결과 저장, ORM 정합성, testbed 실행 경로를 계속 맞춘다.
- 최종적으로는 API 하나로 기능 A/B 결과와 testbed 재현 경로가 연결되게 만든다.
- 배포 전후에는 로컬 재현, DB row 확인, 보고서 생성, 결과 조회가 실제로 끊기지 않는지 계속 확인한다.

### R7 최종 산출물

- 실제 동작하는 scan API
- 결과 조회 가능한 DB 구조
- 공통 testbed 실행 경로
- 보고서 조회/생성 경로

### R7이 충돌 없이 작업하려면

- 팀원별 파일 경계를 세부기획서와 이 문서 기준으로 유지한다.
- testbed와 본 파이프라인 DB의 역할을 섞지 않는다.
- 문서에서 제거된 기준 정보를 임의로 압축하거나 삭제하지 않는다.

## 4. 공통 파이프라인과 역할 연결

이 섹션은 `누가 어느 시점에 무엇을 넘겨받고`, `어떤 상태를 다음 사람에게 넘기며`, `끝까지 무엇을 확인해야 하는지`를 기능 기준으로 보는 섹션이다.

### 기능 A 전체 흐름

1. R7이 scan API에서 세션을 생성한다.
2. R2가 Phase 1에서 공용 공격 패턴을 로드하고 대량 스캔한다.
3. R1이 안전해 보인 케이스를 Red Agent로 우회 공격한다.
4. R3가 취약 응답에 대해 방어 응답을 생성한다.
5. R3와 R1이 같은 공격에 대해 재판정과 재검증을 수행한다.
6. R7이 결과를 DB, 리포트, 대시보드에 연결한다.

### 기능 A에서 팀이 계속 확인해야 하는 것

- R2가 넘긴 공격 기준이 R1 우회 공격과 충돌하지 않는지 확인한다.
- R1 Judge 결과와 R3 verify 결과가 같은 계약을 보는지 확인한다.
- R7 저장 스키마가 R6 화면에서 필요한 필드를 빠뜨리지 않는지 확인한다.
- 기능 A 결과 묶음이 `공격 - 원응답 - 판정 - 방어 응답 - 재판정` 으로 유지되는지 확인한다.

### 기능 B 전체 흐름

1. R5가 직원 요청을 받는다.
2. 정책 엔진이 요청을 검사한다.
3. 허용 요청만 adapter를 통해 실제 AI로 전달한다.
4. 응답 마스킹과 로그 저장을 수행한다.
5. R7 DB 계층이 결과를 저장한다.

### 기능 B에서 팀이 계속 확인해야 하는 것

- 정책 판정 결과와 DB 저장 구조가 운영자가 읽을 수 있는 형태인지 확인한다.
- adapter 계약 변경이 monitoring proxy 에 누락 없이 반영되는지 확인한다.
- 차단 케이스와 허용 케이스 둘 다 로그가 남는지 확인한다.

### testbed가 들어가는 위치

- testbed는 기능 A를 위한 공통 공격 타깃이다.
- `testbed/target_chatbot` 은 실제 공격 대상 챗봇이다.
- `testbed/tool_gateway` 는 이 챗봇이 호출하는 내부 도구 서버다.
- 고객 챗봇을 직접 붙이기 전에도 팀은 testbed로 공격 시나리오를 재현할 수 있다.

### testbed에서 팀이 계속 확인해야 하는 것

- testbed 취약점 재현 케이스가 기능 A 공격 패턴과 완전히 따로 놀지 않는지 확인한다.
- testbed 도구 계약 변경이 target chatbot, gateway, DB schema 와 같이 맞는지 확인한다.
- weak / strict 비교 결과가 문서 설명과 실제 동작이 같은지 확인한다.

## 5. testbed target chatbot 최종 구조

### 핵심 파일

- `testbed/target_chatbot/app.py`
- `testbed/target_chatbot/prompts.py`
- `testbed/target_chatbot/tool_router.py`
- `testbed/tool_gateway/app.py`
- `testbed/tool_gateway/db_tools.py`
- `testbed/tool_gateway/internal_api.py`

### weak / strict 를 나눈 이유

- `weak` 는 취약점 재현용이다. 내부 운영 정보와 느슨한 권한 규칙이 들어가 있어 공격 성공 케이스를 만들기 쉽다.
- `strict` 는 방어 비교용이다. 시스템 프롬프트 비공개, 타 고객 정보 비공개, 관리자급 도구 실행 제한, 문서 주입 무시, 마스킹 규칙 등을 넣는다.
- 둘은 서로 다른 제품이 아니라, 같은 챗봇에 대해 보안 규칙 적용 전후를 비교하기 위한 두 모드다.

### 처리 단계

1. 사용자가 `POST /chat` 으로 메시지를 보낸다.
2. chatbot이 `weak` 또는 `strict` 시스템 프롬프트를 붙여 Ollama에 전달한다.
3. 모델이 `<tool_call>...</tool_call>` 형식의 도구 호출을 출력하면 tool router가 이를 파싱한다.
4. tool router가 tool gateway로 요청을 전달한다.
5. tool gateway가 testbed DB, KB, 메일 샌드박스, 내부 API를 실제로 조회하거나 실행한다.
6. tool 결과가 다시 모델 입력으로 들어가고, 최종 응답이 생성된다.

### 팀 테스트 기준

- weak 모드 기본값으로 먼저 취약 응답을 확인한다.
- 같은 질문을 strict 모드로 다시 보내 차이를 확인한다.
- 그 다음 AgentShield scan API의 target URL을 `http://localhost:8010/chat` 으로 넣어 기능 A 전체 흐름을 확인한다.

## 6. 팀 충돌을 막기 위한 최종 규칙

1. target 포맷 처리 로직은 adapter에 둔다.
2. 공격 데이터 기준본은 DB로 맞춘다.
3. tool 이름과 Judge 계약을 문서 없이 바꾸지 않는다.
4. Blue Agent를 방어 코드 생성기로만 축소 해석하지 않는다.
5. testbed는 기능 B 본체가 아니라 기능 A 검증 환경이라는 해석을 유지한다.
6. 파일 단위 소유 범위는 세부기획서와 이 문서를 같이 갱신하면서 유지한다.
