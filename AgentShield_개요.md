# AgentShield 개요

이 문서는 팀 내부 기준으로 AgentShield가 무엇을 만들기 위해 시작됐고, 지금 어디까지 방향이 정리됐는지, 그리고 최종적으로 어떤 형태의 제품을 목표로 하는지 이해하기 위한 문서다. README가 외부 공개용 입구 문서라면, 이 문서는 팀원들이 같은 그림을 보고 구현 우선순위를 맞추기 위한 내부 방향 문서다.

## 1. 우리가 처음 풀고 싶었던 문제

프로젝트를 시작할 때 팀이 잡았던 문제의식은 명확했다. 기업이나 기관이 운영하는 AI 챗봇은 단순 답변 생성기가 아니라 내부 문서 검색, 고객정보 조회, 환불 처리, 이메일 발송, 계정 조작 같은 실제 업무 도구에 연결되기 때문에, 공격이 성공했을 때 피해가 단순한 이상 응답을 넘어서 실제 정보 유출과 권한 오남용으로 이어질 수 있다는 점이었다.

따라서 처음 목표는 다음 두 가지를 동시에 다루는 것이었다.

- 외부 고객 챗봇을 공격해 실제 취약점을 찾아내는 것
- 내부 직원이 사용하는 AI 요청을 통제해 운영 단계의 위험을 줄이는 것

이 두 흐름이 지금의 기능 A와 기능 B로 분리되어 남아 있다.

## 2. 처음 목표와 현재 목표, 그리고 최종 목적

### 처음 목표

- OWASP LLM 주요 위험을 기준으로 공격 시나리오를 자동 생성하고 검사한다.
- 취약한 챗봇 응답을 찾아내고, 방어 코드나 정책도 만들어본다.
- 멀티에이전트 구조를 통해 공격, 판정, 방어, 검증을 분리한다.

### 현재 정리된 목표

- 현재 1차 제품은 `고객이 제공한 단일 target URL`을 기준으로 검증과 개선안을 제시하는 시스템이다.
- 고객은 URL 하나와 필요 시 API key만 제공하면 된다.
- Blue Agent의 1차 산출물은 `방어 응답`이다.
- 상시 런타임 차단 프록시는 장기 목표이고, 지금 MVP의 핵심은 `검증 + 개선안 생성`이다.

### 최종 목적

- 고객이 실제 운영 중인 AI 챗봇 또는 에이전트를 URL 단위로 검사할 수 있어야 한다.
- 공격 성공 여부만이 아니라, 어떤 응답이 왜 문제였는지와 어떤 개선안이 더 적절한지까지 보여줘야 한다.
- 장기적으로는 방어 응답, 방어 정책, 운영 프록시까지 이어지는 형태로 확장 가능해야 한다.

즉 AgentShield의 최종 목적은 `AI 서비스의 보안 상태를 진단하고, 개선안과 운영 가드레일까지 연결 가능한 기반을 만드는 것`이다.

## 3. 현재 팀이 공통으로 맞춰야 하는 핵심 해석

- 기능 A는 `고객 챗봇 검증 + 개선안 생성` 경로다.
- 기능 B는 `직원 AI 사용 통제` 경로다.
- testbed는 기능 B 본체가 아니라, 기능 A를 재현하고 비교 검증하기 위한 공통 공격 타깃 환경이다.
- Blue Agent는 방어 코드 생성기만이 아니라 `방어 응답 생성기`로 먼저 이해해야 한다.
- 데이터셋과 보고서의 기준 묶음은 `공격 - 원응답 - 판정 - 방어 응답 - 재판정` 이다.

## 4. 기능 A와 기능 B의 제품 의미

### 기능 A. AI 보안 테스트 자동화

기능 A는 고객이 검사받고 싶은 챗봇 URL 하나를 주면, AgentShield가 내부에서 공격을 보내고, 결과를 판정하고, 더 안전한 방어 응답까지 제시하는 흐름이다.

주요 단계는 다음과 같다.

1. 공용 공격 패턴으로 대량 스캔을 수행한다.
2. 처음에는 안전해 보였던 케이스를 Red Agent가 다시 우회 공격한다.
3. 취약 응답에 대해 Blue Agent가 더 안전한 방어 응답을 만든다.
4. Judge와 Verify 계층이 그 방어 응답이 실제로 더 안전한지 다시 확인한다.
5. 결과를 DB, 보고서, 대시보드로 정리한다.

### 기능 B. 직원 AI 사용 모니터링

기능 B는 외부 고객 챗봇을 공격하는 기능이 아니라, 조직 내부에서 직원이 사용하는 AI 요청을 검사하는 경로다.

주요 단계는 다음과 같다.

1. 직원이 보낸 프롬프트를 정책 엔진으로 검사한다.
2. 민감정보 유출, 부적절 사용, 과도한 요청 등을 판정한다.
3. 허용된 요청만 실제 타깃 AI로 전달한다.
4. 응답 마스킹, usage log 저장, violation 저장을 수행한다.

## 5. testbed의 의미

testbed는 이 프로젝트에서 매우 중요하지만, 제품 본체와 동일한 것은 아니다.

- testbed는 기능 A를 실제처럼 재현하기 위한 내부 타깃 환경이다.
- `testbed/target_chatbot` 은 실제 공격 대상 챗봇이다.
- `testbed/tool_gateway` 는 이 챗봇이 호출하는 내부 도구 서버다.
- testbed DB에는 고객, 주문, 티켓, 환불, 감사 로그 같은 가짜 업무 데이터가 들어 있다.
- weak / strict 두 모드를 통해 보안 규칙 적용 전후를 비교할 수 있다.

즉 testbed는 “학습이 끝난 운영 챗봇 제품”이라기보다, `공격이 실제로 먹히는지`, `방어 응답이 차이를 만드는지`, `도구 오남용이 발생하는지`를 재현하는 기준 환경이다.

## 6. 왜 지금 구조가 필요한가

- 탐지만 하는 도구는 운영팀에게 후속 조치가 부족하다.
- 방어안만 제안하는 도구는 실제 차단 효과를 증명하지 못한다.
- 프롬프트 인젝션, 민감정보 유출, 권한 오남용, 시스템 프롬프트 누출은 서로 연결돼 발생한다.
- 따라서 공격, 판정, 방어 응답 생성, 재검증, 저장, 보고서가 하나의 흐름으로 묶여야 한다.

## 7. 현재 집중하는 OWASP 범위

- `LLM01`: Prompt Injection
- `LLM02`: Sensitive Information Disclosure
- `LLM06`: Excessive Agency
- `LLM07`: System Prompt Leakage

이 네 범위는 기능 A, 기능 B, testbed, defense JSON, Judge 기준, 보고서 구성 전부에 공통으로 영향을 준다.

## 8. 기술 스택과 사용하는 이유

### Backend

- FastAPI
- SQLAlchemy Async
- PostgreSQL
- LangGraph
- Ollama 및 role-based LLM client

언제 쓰는가:

- FastAPI: scan, monitoring, report, auth 같은 API 진입점과 testbed 서비스를 띄울 때 사용한다.
- SQLAlchemy Async: AgentShield 운영 DB의 세션, 결과, 로그 저장에 사용한다.
- PostgreSQL: 공격 패턴, 세션, 결과, monitoring 로그와 testbed 업무 데이터를 저장한다.
- LangGraph: 기능 A의 Phase 1 -> 2 -> 3 -> 4 순서를 하나의 파이프라인으로 묶는다.
- Ollama: Red, Blue, Judge, testbed target chatbot이 로컬 모델을 호출할 때 사용한다.

### Data / Retrieval

- ChromaDB
- `data/attack_patterns/`
- `data/defense_patterns/`
- PostgreSQL `attack_patterns`, `test_sessions`, `test_results`, monitoring 관련 테이블

언제 쓰는가:

- ChromaDB: Phase 2에서 과거 성공 공격을 찾을 때, Phase 3에서 유사 방어 예시를 찾을 때, testbed 내부 KB 검색을 할 때 사용한다.
- `data/attack_patterns/`: DB가 비었거나 로컬 fallback이 필요할 때 쓰는 원본 공격 자산이다.
- `data/defense_patterns/`: Blue Agent가 참고할 방어 예시 자산이다.
- PostgreSQL `attack_patterns`: 팀 공용 공격 기준본이다.
- PostgreSQL `test_sessions`, `test_results`: 실제 스캔 결과와 재검증 결과 저장소다.
- monitoring 관련 테이블: 기능 B의 usage log, violation 저장소다.

여기서 RAG는 다음 상황에서 실제로 사용된다.

- 기능 A Phase 2: 과거 성공 공격을 다시 찾아 Red Agent 변형 공격 품질을 높일 때
- 기능 A Phase 3: 유사 방어 응답 또는 정책 예시를 찾아 Blue Agent 출력을 보조할 때
- testbed 내부 API: `/kb/search` 경로로 챗봇이 내부 문서를 조회할 때

### Runtime Components

- `defense_proxy/`: 방어 정책 적용 후 재검증 프록시
- `monitoring_proxy/`: 직원 AI 사용 모니터링 프록시
- `testbed/`: 타깃 챗봇, tool gateway, KB, 실제 DB

언제 쓰는가:

- `defense_proxy/`: Blue가 만든 방어 정책을 실제 입력/출력 필터 형태로 다시 검증할 때 사용한다.
- `monitoring_proxy/`: 직원 AI 사용을 운영 중간에서 통제할 때 사용한다.
- `testbed/`: 고객 챗봇을 직접 붙이기 전후 모두에서 공통 공격 타깃과 도구 오남용 시나리오를 재현할 때 사용한다.

### Frontend

- Next.js dashboard
- scan/monitoring/report 화면

언제 쓰는가:

- 운영자가 스캔 시작, 상태 확인, 결과 조회, 향후 보고서 확인을 할 때 사용한다.

## 9. 고객 통합 방식

현재 구조의 핵심은 `고객이 복잡한 포맷을 직접 맞추지 않아도 된다` 는 점이다.

- 고객은 기본적으로 `target_url` 과 `target_api_key` 만 제공한다.
- 공통 target adapter가 URL 패턴을 보고 provider를 자동 감지한다.
- 내부에서 요청 payload와 응답 파싱 형식을 맞춘다.
- 따라서 각 phase나 proxy가 고객별 포맷을 직접 알 필요가 없다.

현재 지원 방향은 다음과 같다.

- generic `messages -> content`
- OpenAI-style `chat/completions`
- Ollama `api/chat`

## 10. 기존 기획 대비 무엇이 정리되었는가

### 이전 이해

- 각 phase가 타깃 요청 형식을 직접 가정했다.
- 공격 패턴은 파일 자산 위주로 보는 경향이 있었다.
- scan API는 mock 또는 placeholder 중심이었다.
- monitoring outbound도 실제 포워딩 전 단계에 가까웠다.
- Blue Agent는 방어 코드 생성기로만 보이는 경우가 있었다.

### 현재 정리

- target adapter를 공통 계층으로 둔다.
- 공격 패턴은 DB를 팀 공용 기준본으로 관리하고 파일은 fallback 또는 원본 자산으로 본다.
- scan API는 실제 graph 실행 경로를 기본으로 본다.
- monitoring proxy도 실제 포워딩 경로를 사용한다.
- testbed를 팀 공통 검증 환경으로 사용한다.
- Blue Agent는 `방어 응답 생성기 + 보조 정책 생성기`로 해석한다.

즉 제품 방향이 바뀐 것이 아니라, 실제 운영 가능한 구조로 더 구체화된 것이다.

## 11. 지금 팀이 놓치면 안 되는 사실

- 기능 A의 핵심 고객 가치는 `URL 기반 검증 + 개선안 생성`이다.
- 기능 B는 기능 A와 다른 문제를 푸는 운영용 게이트웨이다.
- testbed는 기능 A를 재현하기 위한 환경이지, 최종 고객 제품 자체는 아니다.
- 결과 DB는 원본 기록 저장소다. 학습 후보는 cleaned export를 기준으로 봐야 한다.
- 보고서와 데이터셋의 기준 묶음은 `공격 - 원응답 - 판정 - 방어 응답 - 재판정` 이다.

## 12. 팀 문서 읽는 순서

- `README.md`: 외부 공개용 입구 문서와 저장소 큰 그림
- `AgentShield_개요.md`: 팀 내부 방향, 처음 목표와 현재 목표, 기술 스택 해석
- `AgentShield_세부기획서.md`: 전체 파이프라인과 공통 계약
- `AgentShield_기능별_파이프라인.md`: 역할별 최종 기능 형태와 충돌 방지 기준
- `팀_검수_운영_가이드.md`: JSON 산출, 팀 검토 기준, 실행/점검 절차, 공용 DB 전환 기준
