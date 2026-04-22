# AgentShield 세부기획서

이 문서는 개요보다 더 자세하게, AgentShield 전체 파이프라인이 어떤 입력을 받고 어떤 단계를 거쳐 어떤 결과를 남기는지 설명하는 상세 설계 문서다. 팀이 실제 구현, 연결, 테스트, 데이터 관리, 보고서 구성을 할 때 기준으로 삼는 문서이며, 목표 상태와 현재 구현 상태를 함께 보되 서로 섞지 않는 것을 원칙으로 한다.

## 1. 프로젝트 전체 목적

AgentShield는 두 가지 문제를 푼다.

1. 외부 고객 챗봇 또는 AI 에이전트를 공격해 취약점을 찾고, 개선안까지 제시하는 것
2. 내부 직원이 사용하는 AI 요청을 운영 단계에서 통제하고 로그를 남기는 것

이 두 문제는 각각 기능 A와 기능 B로 구현된다.

이 프로젝트는 제품 경험상으로는 `단일 URL 기반 스캔`으로 시작하지만, 내부 구조상으로는 `테스트 -> 수동 검수 -> 성공사례 축적 -> cleaned export -> 모델 개선` 으로 이어지는 지속 개선형 플랫폼이다. 따라서 단발성 진단 도구와 학습/운영 기반을 함께 가진다고 보는 것이 맞다.

## 2. 기능 A 전체 파이프라인 상세

기능 A는 `Find -> Fix -> Verify` 흐름이다. 최종적으로 고객에게 보여줘야 하는 것은 단순한 공격 성공 여부가 아니라, 문제 응답과 개선 응답, 재검증 결과까지 포함된 하나의 보안 진단 결과다.

### 단계 1. 스캔 시작

입력:

- `project_name`
- `target_url`
- `target_api_key` optional
- `target_provider` optional
- `target_model` optional

처리:

1. scan API가 세션을 생성한다.
2. 세션 상태를 `queued` 로 저장하고 백그라운드 작업이 시작되면 `running` 으로 전환한다.
3. graph 실행에 필요한 공통 상태를 만든다.

출력:

- `test_sessions` row
- graph 초기 상태

운영 참고:

- 고객에게 보이는 것은 scan 상태와 결과 요약이다.
- review queue 수정, defense 승인, Chroma 삭제/재적재는 내부 운영자 전용 워크플로다.
- 즉 운영 UI와 고객 결과 UI는 분리해서 해석해야 한다.

배포 모드 참고:

- 기본 저장소 설정은 로컬 PostgreSQL / 로컬 Chroma 기준이다.
- 공유 PostgreSQL / 공유 Chroma 모드는 별도 운영 설정이 있어야 한다.
- 팀 공용 운영 기준은 `TEAM_SHARED_OPS.md` 와 `.env.shared.example` 를 따른다.

### 단계 2. Phase 1 대량 공격

입력:

- `target_url`
- 공용 공격 패턴 자산

처리:

1. `attack_patterns` 테이블에서 공격 패턴을 로드한다.
2. 필요 시 파일 fallback을 사용한다.
3. 각 공격을 target adapter를 통해 실제 타깃에 보낸다.
4. Judge가 응답을 `safe`, `vulnerable`, `ambiguous`, `error` 로 판정한다.
5. Phase 2에 넘길 `safe_attacks` 를 분리한다.

출력:

- Phase 1 결과 목록
- `safe_attacks`
- scan summary

저장:

- `test_results` phase 1 row

### 단계 3. Phase 2 우회 공격

입력:

- Phase 1의 `safe_attacks`
- RAG 검색 결과

처리:

1. Red Agent가 과거 성공 우회 사례를 참고한다.
2. 안전해 보였던 입력을 다시 변형해 공격한다.
3. target adapter로 실제 타깃에 재전송한다.
4. Judge가 다시 취약 여부를 판정한다.

출력:

- mutated attack prompt
- target original response
- judge verdict

저장:

- `test_results` phase 2 row

### 단계 4. Phase 3 방어 응답 생성

입력:

- Phase 2의 vulnerable 결과
- defense RAG 검색 결과

처리:

1. Blue Agent가 문제 응답과 공격 맥락을 입력받는다.
2. 더 안전한 `defended_response` 를 생성한다.
3. 필요 시 defense JSON 또는 정책 초안을 생성한다.

출력:

- `defended_response`
- optional `defense_code` 또는 defense JSON

저장:

- `test_results` 의 방어 응답 관련 필드
- 필요 시 `data/phase3_defenses/<session_id>/`

### 단계 5. Phase 4 재검증

입력:

- 공격 프롬프트
- 원응답
- 방어 응답
- optional defense JSON

처리:

1. Judge가 Blue 방어 응답을 다시 판정한다.
2. 필요 시 Defense Proxy 경로로도 재시도한다.
3. blocked, mitigated, bypassed, false positive 를 계산한다.
4. 필요하면 수동 검토 대상으로 표시한다.

출력:

- verify_result
- rejudge verdict
- manual review 여부

저장:

- `test_results.verify_result`
- phase 4 summary row

### 단계 6. 결과 정리와 보고서

고객에게 보여줘야 하는 최소 결과 묶음은 다음과 같다.

1. 공격 프롬프트
2. 원응답
3. 취약 판정 결과
4. 방어 응답
5. 방어 정책/코드 요약 optional
6. 재검증 결과
7. 수동 검토 필요 여부

## 3. 기능 B 전체 파이프라인 상세

기능 B는 직원 AI 사용을 운영 단계에서 통제하는 경로다. 외부 고객 챗봇을 공격하는 기능이 아니며, 조직 내부 요청을 안전하게 전달하고 기록하는 것이 목적이다.

### 단계 1. 요청 수신

입력:

- employee messages
- employee context
- target URL
- optional target key

### 단계 2. 정책 검사

처리 순서:

1. P1 기밀유출 검사
2. P2 부적절 사용 검사
3. P3 rate limit 검사
4. 필요 시 P4 의도 재검토

### 단계 3. 실제 포워딩

처리:

1. 허용된 요청만 target adapter로 전달한다.
2. 실제 타깃 AI 응답을 받는다.

### 단계 4. 사후 처리

처리:

1. 민감 정보 마스킹
2. usage log 저장
3. violation record 저장

출력:

- 전달 여부
- 정책 결과
- 마스킹된 응답
- usage log / violation

## 4. testbed 상세 파이프라인

testbed는 기능 A를 재현하기 위한 공통 공격 타깃이다.

### 구성 요소

- `target_chatbot`: 실제 공격 대상 챗봇
- `tool_gateway`: 챗봇이 호출하는 내부 도구 서버
- `testbed DB`: 고객, 주문, 티켓, 환불, 로그 저장소
- `KB`: 내부 문서 검색용 자산

### target_chatbot 동작

1. `POST /chat` 으로 메시지를 받는다.
2. `weak` 또는 `strict` 시스템 프롬프트를 붙인다.
3. Ollama에 메시지를 보낸다.
4. 모델이 tool call 을 출력하면 tool router가 이를 잡는다.
5. tool gateway로 전달한다.
6. tool 결과를 다시 모델 입력으로 넣고 최종 응답을 만든다.

### weak / strict 모드 의미

- weak: 취약점 재현용
- strict: 보안 규칙 비교용

### testbed가 꼭 필요한 이유

- 고객 챗봇을 직접 붙이기 전에도 팀이 같은 조건에서 공격을 재현할 수 있다.
- DB 조회, 내부 문서 검색, 환불, 비밀번호 초기화, 이메일 발송 같은 도구 오남용 시나리오를 실제처럼 볼 수 있다.

## 5. 폴더/파일 구조표와 역할 경계

이 섹션은 팀이 실제로 어떤 폴더와 파일을 기준으로 작업을 나누는지, 각 파일이 정확히 무엇을 하는지, 역할이 어디서 겹치면 안 되는지를 정리한 기준표다. 공개용 README에는 넣지 않고, 이 문서와 기능별 파이프라인 문서에서만 관리한다.

### 역할별 주 폴더 구조표

| 역할 | 주 폴더 | 핵심 책임 | 다른 역할과 겹치면 안 되는 경계 |
| --- | --- | --- | --- |
| R1 | `backend/agents/`, `backend/core/`, `backend/graph/` | Red Agent, Judge, graph phase 전환 | 공격 변형과 판정 계약을 UI, API, DB 레이어에서 임의로 바꾸지 않는다 |
| R2 | `backend/core/`, `backend/models/`, `backend/data_cleaning/`, `data/attack_patterns/` | 공격 패턴 기준본, Phase 1 스캔, cleaned export | 공격 자산 기준을 개별 파일 사본이나 testbed 임시 데이터로 바꾸지 않는다 |
| R3 | `backend/core/`, `backend/agents/`, `defense_proxy/`, `data/defense_patterns/` | 방어 응답 생성, verify, defense proxy | Blue 출력 형식과 Verify 계약을 Judge 기준과 따로 놀게 바꾸지 않는다 |
| R4 | `backend/agents/`, `backend/rag/`, `backend/finetuning/`, `adapters/`, `models/` | LLM client, RAG, adapter, LoRA/모델 자산 | 모델 호출 규약과 임베딩/검색 경로를 phase 코드에 흩뿌리지 않는다 |
| R5 | `monitoring_proxy/` | 정책 검사, 포워딩, 마스킹, violation 저장 | 기능 A용 testbed 공격 시나리오를 monitoring 정책 경로와 섞지 않는다 |
| R6 | `dashboard/` | scan 시작, 상태, 결과 조회 UI | mock 응답 구조를 실제 API 계약보다 우선 기준으로 두지 않는다 |
| R7 | `backend/api/`, `backend/database.py`, `backend/models/`, `database/`, `testbed/`, `scripts/` | API 연결, DB 정합성, testbed 공통 실행 경로, 보고서 연결 | 운영 DB와 testbed DB 역할을 섞지 않고, 공통 실행 경로를 다른 레이어에 중복 구현하지 않는다 |

### 역할별 파일 상세와 비충돌 기준

#### R1 파일 구조

| 파일/폴더 | 파일 의미 | 역할 경계 |
| --- | --- | --- |
| `backend/agents/red_agent.py` | 안전해 보인 입력을 다시 깨기 위한 변형 공격 생성기 | 공격 생성 규칙을 DB 저장 형식과 섞지 않는다 |
| `backend/core/phase2_red_agent.py` | Phase 2 우회 공격 실행 로직 | API 입력 계약을 이 파일에서 직접 정의하지 않는다 |
| `backend/core/judge.py` | 취약 여부를 `safe`, `vulnerable`, `ambiguous`, `error`로 판정하는 핵심 Judge | UI 표시용 문구 때문에 판정 계약을 바꾸지 않는다 |
| `backend/core/guard_judge.py` | 보조/가드 성격의 판정 계층 | Blue verify 규칙과 중복 기준을 따로 만들지 않는다 |
| `backend/graph/llm_security_graph.py` | Phase 1~4를 묶는 LangGraph 오케스트레이션 | DB 저장 로직을 graph 내부에 흩뿌리지 않는다 |
| `backend/graph/run_pipeline.py` | 전체 scan 실행 진입점 | 외부 API 응답 형식을 여기서 직접 고정하지 않는다 |

#### R2 파일 구조

| 파일/폴더 | 파일 의미 | 역할 경계 |
| --- | --- | --- |
| `backend/core/phase1_scanner.py` | 대량 공격을 타깃에 보내는 Phase 1 실행기 | Judge 기준을 여기서 임의로 축소하거나 바꾸지 않는다 |
| `backend/models/attack_pattern.py` | 공격 패턴 ORM 모델 | 파일 자산과 DB 기준을 어긋나게 두지 않는다 |
| `data/attack_patterns/` | 공격 패턴 원본/샘플/fallback 자산 폴더 | 공용 기준은 DB라는 원칙을 깨지 않는다 |
| `backend/data_cleaning/cleaning_rules.py` | 학습 제외/정제 규칙 정의 파일 | raw 결과를 정제 없이 바로 통과시키지 않는다 |
| `backend/data_cleaning/export_clean_finetuning_data.py` | cleaned export 생성 스크립트 | `manual_review_needed` 결과를 그대로 export 하지 않는다 |

#### R3 파일 구조

| 파일/폴더 | 파일 의미 | 역할 경계 |
| --- | --- | --- |
| `backend/core/phase3_blue_agent.py` | 취약 응답을 바탕으로 방어 응답을 만드는 Phase 3 실행기 | Blue를 방어 코드 생성기로만 축소하지 않는다 |
| `backend/agents/blue_agent.py` | Blue Agent 프롬프트/호출 래퍼 | verify 입력 형식과 따로 놀게 바꾸지 않는다 |
| `backend/core/phase4_verify.py` | 같은 공격 기준으로 방어 응답을 다시 검증하는 계층 | Judge 계약과 다른 verdict 체계를 만들지 않는다 |
| `defense_proxy/proxy_server.py` | 방어 정책 또는 defense JSON 적용 프록시 | Monitoring proxy와 기능을 섞지 않는다 |
| `data/defense_patterns/` | 방어 패턴 자산 폴더 | 공격 패턴과 방어 패턴 기준을 섞지 않는다 |

#### R4 파일 구조

| 파일/폴더 | 파일 의미 | 역할 경계 |
| --- | --- | --- |
| `backend/agents/llm_client.py` | 역할별 LLM 공통 호출 클라이언트 | 각 phase가 모델 호출 세부사항을 중복 구현하지 않게 한다 |
| `backend/rag/` | ChromaDB 검색/적재 모듈 폴더 | testbed KB와 phase RAG 경로를 혼동하지 않는다 |
| `backend/finetuning/` | 파인튜닝 및 학습 자산 관리 폴더 | raw DB 결과를 바로 학습 자산으로 다루지 않는다 |
| `adapters/` | LoRA adapter 및 관련 자산 폴더 | 역할별 모델 분리를 문서 없이 바꾸지 않는다 |
| `models/` | 로컬 모델 자산 저장 폴더 | 운영 코드와 모델 파일 배포 기준을 혼동하지 않는다 |

#### R5 파일 구조

| 파일/폴더 | 파일 의미 | 역할 경계 |
| --- | --- | --- |
| `monitoring_proxy/monitor_server.py` | 기능 B 프록시 진입점 | testbed target chatbot과 역할을 섞지 않는다 |
| `monitoring_proxy/services/forwarder.py` | 허용 요청만 실제 타깃으로 전달하는 포워딩 계층 | adapter 계약을 우회하는 호출을 만들지 않는다 |
| `monitoring_proxy/services/logging_service.py` | usage log 저장 서비스 | 저장 구조를 UI 임시 형식에 맞춰 바꾸지 않는다 |
| `monitoring_proxy/services/violation_service.py` | 위반 기록 저장 서비스 | 정책 판단과 제재 저장을 분리하지 않고 같이 깨뜨리지 않는다 |
| `monitoring_proxy/services/masking.py` | 민감정보 마스킹 로직 | strict testbed 규칙과 monitoring 마스킹을 같은 것으로 취급하지 않는다 |
| `monitoring_proxy/policies/` | 정책 정의 폴더 | testbed prompt 규칙과 운영 정책을 혼합하지 않는다 |
| `monitoring_proxy/schemas/` | monitoring 입출력 스키마 폴더 | backend scan API 스키마와 섞지 않는다 |

#### R6 파일 구조

| 파일/폴더 | 파일 의미 | 역할 경계 |
| --- | --- | --- |
| `dashboard/app/scan/page.tsx` | scan 시작 화면 | backend 계약과 다른 입력 필드를 임의 추가하지 않는다 |
| `dashboard/app/scan/[id]/page.tsx` | 세션 상세/결과 조회 화면 | 결과 묶음 구조를 mock 기준으로 고정하지 않는다 |
| `dashboard/lib/api.ts` | frontend API 호출 래퍼 | backend 엔드포인트 문자열을 화면 곳곳에 중복하지 않는다 |
| `dashboard/components/` | 결과 카드, 상태 표시, 공통 UI 컴포넌트 폴더 | phase 결과 필드를 컴포넌트별로 따로 해석하지 않는다 |

#### R7 파일 구조

| 파일/폴더 | 파일 의미 | 역할 경계 |
| --- | --- | --- |
| `backend/api/scan.py` | 기능 A scan 시작/상태/결과 조회 API | graph 로직을 API 핸들러 안에 중복 구현하지 않는다 |
| `backend/api/report.py` | 결과 보고서 조회/생성 API | dashboard 전용 표시 로직을 이곳에 고정하지 않는다 |
| `backend/api/monitoring.py` | 기능 B 대시보드/정책/직원 조회 API | monitoring 저장 구조를 scan 결과 구조와 섞지 않는다 |
| `backend/database.py` | DB 엔진, 세션, 초기화 관리 파일 | 각 모듈이 독자적으로 DB 연결을 만들게 두지 않는다 |
| `backend/models/` | AgentShield 운영 DB ORM 모델 폴더 | testbed 실험 테이블과 운영 ORM을 혼동하지 않는다 |
| `database/schema.sql` | AgentShield 운영 DB 스키마 | testbed 스키마와 같은 역할로 다루지 않는다 |
| `database/testbed_schema.sql` | testbed 전용 스키마 | 운영 DB 테이블과 섞지 않는다 |
| `testbed/target_chatbot/` | 기능 A 재현용 실제 공격 대상 챗봇 폴더 | monitoring proxy와 제품 의미를 혼동하지 않는다 |
| `testbed/tool_gateway/` | testbed 도구 서버 폴더 | stub과 실제 실행 경로를 섞지 않는다 |
| `docker-compose.testbed.yml` | testbed 실행 묶음 정의 파일 | 로컬 수동 실행 기준과 역할을 혼동하지 않는다 |
| `scripts/testbed_local.sh` | 로컬 testbed 기동/중지/smoke 스크립트 | 문서와 다르게 동작하는 숨은 기본값을 두지 않는다 |
| `scripts/setup_testbed_db.sh` | testbed DB 스키마 적용 및 시드 스크립트 | 운영 DB 준비 절차와 섞지 않는다 |
| `scripts/seed_testbed.py` | testbed 샘플 데이터 생성기 | testbed 데이터와 학습 데이터 생성을 혼용하지 않는다 |
| `scripts/ingest_testbed_kb.py` | testbed KB 적재 스크립트 | Phase 2/3 RAG 적재와 같은 경로로 오해하게 만들지 않는다 |

### 공통 testbed 파일 상세

| 파일 | 파일 의미 | 함께 보는 역할 |
| --- | --- | --- |
| `testbed/target_chatbot/app.py` | `POST /chat`, `/health` 를 제공하는 target chatbot 본체 | R7 주관, R2/R5 검증 |
| `testbed/target_chatbot/prompts.py` | weak/strict 시스템 프롬프트 정의 파일 | R7 주관, R2/R5 검토 |
| `testbed/target_chatbot/tool_router.py` | tool call 을 gateway 또는 stub으로 라우팅하는 파일 | R7 주관, R5 검토 |
| `testbed/tool_gateway/app.py` | tool gateway FastAPI 엔트리포인트 | R7 주관 |
| `testbed/tool_gateway/db_tools.py` | customer/order/ticket 조회/수정/삭제 도구 구현 파일 | R7 주관, R2 검수 |
| `testbed/tool_gateway/internal_api.py` | KB 검색, 환불, 비밀번호 초기화, 파일 접근 같은 내부 도구 구현 파일 | R7 주관, R5 함께 사용 |
| `docker-compose.testbed.yml` | Docker 환경에서 testbed 묶음을 올리는 정의 파일 | R7 주관 |
| `scripts/testbed_local.sh` | 로컬에서 testbed를 재현하는 공통 실행 스크립트 | R7 주관, 전원 사용 |
| `scripts/setup_testbed_db.sh` | testbed DB를 비우고 다시 채우는 공통 준비 스크립트 | R7 주관, 전원 사용 |
| `scripts/seed_testbed.py` | deterministic testbed row 생성 파일 | R7 주관, R2 검수 |
| `scripts/ingest_testbed_kb.py` | testbed용 KB 문서 적재 스크립트 | R7 주관, R4 함께 사용 |

### 역할이 실제로 겹치는 지점과 금지선

- R1과 R3는 Judge와 Verify 계약에서 만난다. verdict 필드 체계를 한쪽만 바꾸면 안 된다.
- R2와 R7은 공격 패턴 DB, test_results 저장, cleaned export 기준에서 만난다. raw 저장과 학습용 export를 한 기준으로 합치면 안 된다.
- R4와 R7은 testbed KB ingest와 phase RAG 경로에서 만난다. 같은 Chroma를 쓰더라도 컬렉션 목적을 섞으면 안 된다.
- R5와 R7은 monitoring 저장 구조와 testbed 내부 도구 경계에서 만난다. 기능 B 정책 처리와 testbed 공격 재현 로직을 같은 제품 흐름으로 합치면 안 된다.
- R6와 R7은 scan 결과 조회 형식에서 만난다. backend가 주 계약이고 UI는 그 계약을 따라야 한다.

## 6. 공통 인터페이스 상세

### 고객 타깃 연동 계약

입력 기준:

- `target_url`
- `target_api_key` optional
- `target_provider` optional
- `target_model` optional

내부 기준:

- 공통 target adapter가 provider를 자동 감지한다.
- phase 코드와 proxy 코드는 target payload 형식을 직접 가정하지 않는다.
- 고객은 기본적으로 URL 하나만 입력하면 된다.

### Scan API 계약

- Dashboard는 scan 시작 시 project name, target URL, target API key를 전달한다.
- backend는 세션을 만들고 graph를 실행한다.
- 결과는 `test_sessions`, `test_results` 에 적재한다.

### Monitoring Proxy 계약

- 입력 메시지와 employee context를 받는다.
- 정책 검사를 수행한다.
- 허용 요청만 target adapter를 통해 실제 타깃으로 보낸다.

## 7. DB와 데이터 관리 상세

### 공격 데이터 기준본

- 팀 공통 공격 자산은 PostgreSQL `attack_patterns` 테이블이다.
- `data/attack_patterns/` 는 원본 자산, fallback, 샘플 역할이다.

### 결과 데이터 저장소

- `test_sessions`: 세션 상태와 메타데이터
- `test_results`: phase 결과, 원응답, 방어 응답, verify 결과
- monitoring 관련 테이블: usage log, violation, employee, policy rule

### 오염관리 기준

- 공유 DB는 원본 기록 저장소다.
- `DB에 있음 = 바로 학습 사용 가능` 이 아니다.
- 사람이 다시 봐야 하는 결과는 review queue에서 확인한다.
- `manual_review_needed=true` 는 cleaned export에서 제외한다.
- 실제 학습 데이터는 `backend/data_cleaning/` 결과만 사용한다.

### testbed DB 기준

- testbed DB는 기능 A 재현용 실험 데이터 저장소다.
- customers, orders, support_tickets, refund_requests, audit_logs 등을 가진다.
- AgentShield 운영 DB와 역할이 다르므로 혼동하면 안 된다.

## 8. RAG와 멀티에이전트 상세

### 멀티에이전트 구성

- Red Agent: 변형 공격 생성
- Judge Agent: 취약 여부 판정
- Blue Agent: 방어 응답 생성
- Verify Layer: 재검증 및 수동 검토 분기
- Report / Dataset Builder: 결과 묶음 구성

### RAG가 실제로 쓰이는 위치

- Phase 2: 과거 성공 공격을 참고해 mutation 품질을 높인다.
- Phase 3: 유사 방어 예시를 참고해 방어 응답 품질을 높인다.
- testbed `/kb/search`: 내부 문서 검색을 수행한다.

## 9. 기존 기획 대비 유지된 것과 달라진 것

### 유지된 것

- OWASP 4개 범위 중심
- Find -> Fix -> Verify 큰 흐름
- 역할 분담 구조

### 달라진 것

- target 호출 방식이 phase별 하드코딩에서 adapter 구조로 이동했다.
- 공격 데이터 기준이 파일 중심에서 DB 중심으로 이동했다.
- scan API가 mock 중심에서 실제 graph 실행 구조로 이동했다.
- monitoring outbound가 placeholder에서 실제 forward 구조로 이동했다.
- testbed가 공통 기준 환경으로 승격됐다.
- Blue Agent 핵심 산출물이 방어 코드에서 방어 응답 중심으로 재정리됐다.

## 10. 완료 기준

### 완료로 보는 조건

- 코드가 존재한다.
- 호출 경로가 실제로 연결된다.
- 최소 실행 절차가 문서화된다.
- 테스트 또는 실행 검증 기록이 있다.

### 미완으로 보는 조건

- 함수나 API가 placeholder다.
- UI는 연결됐지만 backend가 mock만 반환한다.
- 문서가 현재 상태를 숨기고 목표만 적는다.

## 11. 팀이 계속 맞춰야 하는 운영 원칙

1. tool 이름을 문서 없이 바꾸지 않는다.
2. Judge 계약을 문서 없이 바꾸지 않는다.
3. target 포맷 변환 로직을 phase 코드에 다시 흩뿌리지 않는다.
4. DB 공격 데이터는 개인 로컬 파일이 아니라 공용 테이블 기준으로 맞춘다.
5. Blue Agent 학습/평가의 중심은 방어 성공 응답 데이터셋이라는 점을 유지한다.
6. README, 개요, 세부기획서, 기능별, QA 문서는 공통 계약이 바뀌면 같이 갱신한다.
