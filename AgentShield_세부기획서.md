# AgentShield 세부기획서

이 문서는 팀 전체가 같은 결과물을 만들기 위한 운영 기준 문서다. 아이디어 메모가 아니라 역할, 산출물, 공통 계약, DB 기준, 통합 우선순위를 고정하는 문서로 사용한다.

## 1. 프로젝트 목표

- 기능 A: AI 챗봇 및 에이전트 보안 테스트 자동화
- 기능 B: 직원 AI 사용 모니터링
- 공통 목표: 공격, 방어, 재검증, 로그, 대시보드 조회를 하나의 제품 흐름으로 연결

## 2. 현재 제품 산출물

### 기능 A 산출물

- Phase 1 스캐너
- Phase 2 Red Agent
- Judge 계층
- Phase 3 Blue Agent 방어 응답 및 방어 정책 생성
- Phase 4 Verify 및 재판정
- Defense Proxy
- Scan API / Dashboard
- 결과 저장 및 리포트 기반 데이터

### 기능 B 산출물

- Monitoring Proxy 요청 흐름
- 정책 탐지기
- 의도 재검토
- 실제 target forwarder
- 사용 로그 / 위반 기록 저장

### 공통 산출물

- PostgreSQL schema와 ORM
- ChromaDB 자산
- role-based LLM client
- target adapter
- testbed

## 3. 설계 원칙

- 역할은 분리하되 인터페이스는 팀 기준으로 통일한다.
- 한 사람이 맡은 폴더라도 공통 계약을 독자적으로 바꾸지 않는다.
- 공통 규약 변경 시 README, 개요, 세부기획서, 기능별 파이프라인을 같이 갱신한다.
- 구현 상태와 목표 상태를 섞어 쓰지 않는다.

## 4. 역할 정의

### R1. 공격 고도화 및 판정 체계

- 소유 범위: Phase 2, Judge, graph orchestration
- 핵심 파일: `backend/core/phase2_red_agent.py`, `backend/core/judge.py`, `backend/graph/`
- 책임:
  - safe 케이스를 변형 공격으로 재시도
  - judge 기준을 안정적으로 유지
  - phase 간 상태 구조를 통일

### R2. 공격 데이터 및 Phase 1

- 소유 범위: 공격 패턴 수집/정제, Phase 1 스캐너
- 핵심 파일: `backend/core/phase1_scanner.py`, `backend/models/attack_pattern.py`, `data/attack_patterns/`
- 책임:
  - 공통 attack DB 기준본 관리
  - 카테고리, 심각도, 출처 정합성 유지
  - DB 우선 로드와 파일 fallback 정책 유지

### R3. 방어 생성 및 재검증

- 소유 범위: Phase 3, Phase 4, Defense Proxy
- 핵심 파일: `backend/core/phase3_blue_agent.py`, `backend/core/phase4_verify.py`, `defense_proxy/proxy_server.py`
- 책임:
  - 취약점별 방어 응답 생성
  - 필요 시 defense JSON / 정책 생성
  - Judge 재판정 및 선택적 proxy 적용 검증
  - blocked rate / false positive rate 기준 유지

### R4. LLM infra / RAG / adapter 자산

- 소유 범위: LLM client, RAG, 파인튜닝, adapters
- 핵심 파일: `backend/agents/llm_client.py`, `backend/rag/`, `backend/finetuning/`, `adapters/`
- 책임:
  - 역할별 모델 호출 안정화
  - ChromaDB ingest/search
  - adapter 및 모델 자산 관리

### R5. 직원 AI 모니터링

- 소유 범위: Monitoring Proxy와 정책 엔진
- 핵심 파일: `monitoring_proxy/`
- 책임:
  - P1/P2/P3/P4 흐름 유지
  - allowed 요청만 target forward
  - usage log / violation 생성 경로 관리

### R6. 대시보드

- 소유 범위: scan, monitoring, report UI
- 핵심 파일: `dashboard/`
- 책임:
  - scan 시작, 상태, 결과 조회 화면
  - 운영팀이 이해 가능한 시각화
  - backend API 계약 반영

### R7. API / DB / 리포트

- 소유 범위: FastAPI 엔드포인트, ORM, DB 세션, 리포트
- 핵심 파일: `backend/api/`, `backend/database.py`, `backend/models/`, `database/`
- 책임:
  - API 계약 유지
  - DB 테이블 정합성 유지
  - 세션/결과/리포트 조회 경로 제공

## 5. 공통 인터페이스

### 고객 타겟 연동 계약

입력 기준:

- `target_url`
- `target_api_key` optional
- `target_provider` optional, 기본 `auto`
- `target_model` optional

내부 동작 기준:

- 공통 target adapter가 provider를 자동 감지한다.
- phase 코드와 proxy 코드는 target payload 형식을 직접 가정하지 않는다.
- 고객 검증 요청 기준으로는 target URL 하나만 받는다.
- 같은 URL에 대해 원본 테스트와 방어 재테스트를 내부에서 반복 수행할 수 있다.

현재 adapter 지원 목표:

- generic `messages -> content`
- OpenAI-style `chat/completions`
- Ollama `api/chat`

### Scan API 계약

- Dashboard는 scan 시작 시 project name, target URL, target API key를 보낸다.
- backend는 세션 생성 후 graph를 실행한다.
- 결과는 `test_sessions`, `test_results`에 적재한다.
- 고객이 보는 최종 산출물에는 공격 내용, 원래 응답, 방어 응답, 재판정 결과가 포함된다.

### Monitoring Proxy 계약

- 입력 메시지와 employee context를 받고 정책 검사를 수행한다.
- 허용 요청은 target adapter를 통해 실제 타겟으로 전송한다.

## 6. DB 공통 운영 기준

### 공격 데이터 기준본

- 팀 공통 공격 자산은 PostgreSQL `attack_patterns` 테이블을 기준으로 한다.
- 파일 기반 `data/attack_patterns/`는 원본 자산, fallback, 샘플 데이터 역할이다.

### DB팀이 해야 하는 일

- `attack_patterns` 스키마와 인덱스 유지
- 카테고리별 seed 품질 관리
- source, severity, language 메타데이터 정리
- dev seed와 공용 seed를 구분 관리
- testbed와 본 파이프라인이 같은 카테고리 체계를 쓰는지 검증

### 결과 데이터 기준

- `test_sessions`: 세션 시작/완료/실패 상태
- `test_results`: phase 결과, defense_code, verify_result
- monitoring 관련 테이블: usage_log, violation, employee, policy_rule

### 오염관리 기준

- 공유 DB는 원본 기록 저장소다. 실패, 애매함, 오판 가능 케이스까지 같이 들어올 수 있다.
- 따라서 `DB에 있음 = 바로 학습 사용`이 아니다.
- 사람이 다시 봐야 하는 결과는 review queue로 확인하고, `manual_review_needed`가 붙은 건 정제 export에서 제외한다.
- 실제 학습 데이터는 `backend/data_cleaning/`에서 다시 뽑은 결과만 사용한다.
- 팀원 기준 판단은 간단하다: `DB는 원본`, `cleaned export는 학습 후보`.

### DB 접속 점검 기준

- AgentShield 공유 DB 확인: `python -m backend.db_inspect`
- testbed 공유 DB 확인: `nc -z localhost 5433 && echo TESTBED_DB_UP || echo TESTBED_DB_DOWN`
- testbed 직접 조회: `psql "$TESTBED_DB_URL" -c "SELECT COUNT(*) FROM audit_logs;"`

## 7. 기존 기획 대비 변경점

### 바뀌지 않은 것

- OWASP 4개 범위 집중
- Find -> Fix -> Verify라는 큰 흐름
- 역할 분담 구조

### 바뀐 것

- target 호출 방식이 phase별 하드코딩에서 공통 adapter 구조로 이동
- 공격 데이터 관리 기준이 파일 중심에서 DB 중심으로 이동
- scan API가 mock 응답 구조에서 실제 graph 실행 구조로 이동
- monitoring outbound가 placeholder에서 실제 forward 구조로 이동
- develop에 합쳐진 testbed를 팀 공통 기준 환경으로 승격
- Blue Agent의 핵심 산출물을 `방어 규칙 코드`로만 보지 않고 `방어 응답 + 보조 정책`으로 재정의
- 보고서/데이터셋 기준을 `공격 - 원응답 - 방어 응답 - 재판정` 묶음으로 재정리

## 8. 멀티에이전트 구조

- Target Adapter: 고객 URL 하나를 실제 호출 포맷으로 정규화
- Red Agent: 공격 및 변형 공격 생성
- Target LLM: 고객이 검사받는 실제 모델
- Judge Agent: 원응답과 방어 결과의 취약 여부를 최종 판정
- Blue Agent: 방어 응답 생성, 필요 시 방어 정책/코드 생성
- Verify Layer: 같은 공격에 대한 재테스트 및 수동 검토 분기
- Report / Dataset Builder: 보고서와 파인튜닝 데이터셋 구성

## 9. 구현 완료 기준

### 완료로 보는 조건

- 코드가 존재한다.
- 호출 경로가 실제로 연결된다.
- 최소 실행 절차가 문서화된다.
- 테스트 또는 실행 검증 기록이 있다.

### 미완으로 보는 조건

- 함수나 API가 placeholder다.
- UI는 연결됐지만 backend가 mock만 반환한다.
- 문서가 현재 상태를 숨기고 목표만 적는다.

## 10. 문서 운영 원칙

- README는 저장소 입구와 폴더 경계용이다.
- 개요 문서는 제품 설명과 방향 정리용이다.
- 세부기획서는 역할과 공통 계약 고정용이다.
- 기능별 파이프라인은 구현 입력/출력/호출 경로용이다.
- QA 문서는 실행 절차용이다.

## 11. 이번 기준에서 팀이 맞춰야 할 것

- tool 이름을 임의로 바꾸지 않는다.
- judge 계약을 문서 없이 바꾸지 않는다.
- DB 공격 데이터는 개인 로컬 파일이 아니라 공용 테이블 기준으로 맞춘다.
- target 포맷 변환 로직을 phase 코드에 다시 흩뿌리지 않는다.
- 폴더 역할과 소유 범위를 README 기준으로 유지한다.
- Blue Agent 학습/평가의 핵심은 방어 성공 응답 데이터셋 활용이다.
