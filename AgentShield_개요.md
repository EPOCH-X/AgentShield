# AgentShield 개요

## 제품 정의

AgentShield는 기업용 AI 챗봇과 AI 에이전트의 취약점을 자동으로 찾고, Blue Agent가 방어 응답과 방어 정책을 생성하고, Judge가 다시 검증하는 보안 플랫폼이다. 현재 1차 목표는 `단일 target URL 기반 검증 + 개선안 생성`이며, 상시 보호 프록시는 2차 목표다.

## 왜 이 구조가 필요한가

- AI 서비스는 프롬프트 인젝션, 민감정보 유출, 권한 오남용, 시스템 프롬프트 누출에 동시에 노출된다.
- 탐지만 하는 도구는 운영팀 입장에서 후속 조치가 끊긴다.
- 방어 초안만 만드는 도구는 실제 차단율과 오탐률을 증명하지 못한다.
- 운영 조직은 고객 LLM 보안 테스트와 사내 직원용 AI 게이트웨이를 분리해서 볼 수 없다. 두 영역 모두 같은 정책 자산과 연결 기준이 필요하다.

## 제품 범위

### 기능 A. AI 보안 테스트 자동화

1. 공용 공격 데이터셋을 고객 타겟에 대량 전송한다.
2. 안전하게 보였던 응답은 Red Agent가 다시 변형 공격한다.
3. 실제 취약점 케이스에 대해 Blue Agent가 방어 응답을 생성하고, 필요 시 방어 정책/코드를 보조 산출물로 만든다.
4. 같은 공격에 대해 Blue 결과를 Judge가 다시 판정하고, 선택적으로 Defense Proxy 또는 local runtime에서 검증한다.
5. 결과를 Dashboard와 Report API로 보여주고 데이터셋으로 축적한다.

### 기능 B. 직원 AI 사용 모니터링

1. 직원 프롬프트를 정책 엔진으로 검사한다.
2. 애매한 요청은 의도 판정까지 한 번 더 거친다.
3. 허용된 요청만 실제 타겟 AI로 전달한다.
4. 응답을 마스킹하고 로그와 위반 기록을 남긴다.

## 현재 집중하는 OWASP 범위

- `LLM01`: Prompt Injection
- `LLM02`: Sensitive Information Disclosure
- `LLM06`: Excessive Agency
- `LLM07`: System Prompt Leakage

이 네 범위는 기능 A, 기능 B, testbed, defense JSON, judge 기준 전체에 공통으로 영향을 준다.

## 기술 스택

### Backend

- FastAPI
- SQLAlchemy Async
- PostgreSQL
- LangGraph
- Ollama 및 role-based LLM client

### Data / Retrieval

- ChromaDB
- `data/attack_patterns/`, `data/defense_patterns/`
- PostgreSQL `attack_patterns`, `test_sessions`, `test_results`, monitoring 관련 테이블

### Runtime Components

- `defense_proxy/`: 방어 정책 적용 후 재검증 프록시
- `monitoring_proxy/`: 직원 AI 사용 모니터링 프록시
- `testbed/`: 타겟 챗봇, tool gateway, KB, 실제 DB

### Frontend

- Next.js dashboard
- scan/monitoring/report 화면

## 고객 통합 방식

이번 정리의 핵심 설계는 여기다.

- 고객은 기본적으로 `target_url`과 `target_api_key`만 넣는다.
- 공통 target adapter가 URL 패턴을 보고 provider를 자동 감지한다.
- 내부에서 요청 payload와 응답 파싱 형식을 맞춘다.
- 따라서 고객별 포맷 차이를 phase 코드나 proxy 코드가 직접 알 필요가 없다.
- 고객에게 추가 URL을 요구하지 않는다. 검증 관점에서는 하나의 target URL로 충분하다.

현재 지원 방향:

- generic `messages -> content`
- OpenAI-style `chat/completions`
- Ollama `api/chat`

## 기존 기획 대비 변경점

### 현재 기획

- 각 phase가 타겟 요청 형식을 직접 가정했다.
- 공격 패턴은 파일 자산 위주로 생각했다.
- scan API는 최종 연결 전 placeholder/mock 단계였다.
- monitoring outbound는 placeholder 성격이 강했다.

- Blue Agent는 `방어 코드 생성기만`이 아니라 `방어 응답 생성기 + 보조 정책 생성기`로 해석한다.
### 현재 기획

- target adapter를 공통 계층으로 둔다.
- 공격 패턴은 DB를 팀 공용 기준본으로 관리하고 파일은 fallback 또는 원본 자산으로 본다.
- scan API는 실제 graph 실행 경로가 기본이다.
- monitoring proxy도 실제 포워딩 경로를 사용한다.
- develop에서 합쳐진 testbed를 공통 검증 환경으로 삼는다.

즉, 제품 방향이 바뀐 것이 아니라 운영 가능한 통합 구조로 구체화된 것이다.

## 현재 구조에서 중요한 사실

- 로컬 graph 파이프라인은 존재한다.
- dashboard scan 경로도 이미 준비되어 있었다.
- 막혀 있던 핵심은 scan API mock 처리와 format fragmentation이었다.
- 이번 정리는 이 병목을 target adapter와 실경로 연결로 줄이는 방향이다.
- 앞으로 보고서와 데이터셋은 `공격 - 원응답 - 판정 - 방어 응답 - 재판정` 묶음을 기준으로 정리한다.

## 팀이 문서를 보는 순서

- `README.md`: 저장소 입구와 폴더 경계
- `AgentShield_세부기획서.md`: 역할, 인터페이스, 운영 기준
- `AgentShield_기능별_파이프라인.md`: 역할별 상세 입력/출력/호출 경로
- `실전형_테스트_챗봇_구축_가이드.md`: 공통 testbed 기준
- `TEAM_QA_GUIDE.md`: 로컬 QA 기준

## 이번 병합 이후 팀 정렬 기준

- 문서는 압축보다 역할과 경계 복원이 우선이다.
- 목표 상태와 현재 상태를 분리해서 쓴다.
- 고객 통합은 URL과 key 입력을 기준으로 맞춘다.
- 공통 attack DB와 testbed를 팀 단일 기준으로 본다.
- tool 이름과 judge 계약은 문서 없이 바꾸지 않는다.
