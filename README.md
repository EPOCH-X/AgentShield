# AgentShield

AgentShield는 기업이나 기관이 운영하는 AI 챗봇과 AI 에이전트가 얼마나 안전한지 점검하고, 취약한 부분을 찾아 개선안까지 제시하는 보안 프로젝트다. 단순히 “공격이 되는지”만 보는 것이 아니라, 실제로 어떤 입력이 위험했고 어떤 응답이 문제가 되었는지, 그리고 더 안전한 응답은 어떤 모습이어야 하는지까지 한 흐름으로 보여주는 것을 목표로 한다.

이 저장소에는 두 가지 제품 축이 함께 들어 있다.

- 기능 A: 고객이 제공한 챗봇 URL을 대상으로 취약점을 찾고, 방어 응답을 만들고, 다시 검증하는 보안 점검 파이프라인
- 기능 B: 직원이 사용하는 AI 요청을 중간에서 검사하고, 민감정보 유출이나 부적절 사용을 막고, 로그를 남기는 운영용 모니터링 프록시

## AgentShield가 해결하려는 문제

기업이 AI를 붙인 서비스는 단순한 질의응답을 넘어서 고객정보 조회, 문서 검색, 환불 처리, 내부 API 호출 같은 도구 사용까지 포함하는 경우가 많다. 이런 구조에서는 다음과 같은 위험이 동시에 생긴다.

- 프롬프트 인젝션으로 보안 규칙이 무시되는 문제
- 다른 고객의 개인정보나 내부 문서가 노출되는 문제
- 권한이 없는 도구 호출이나 관리자 기능 오남용 문제
- 시스템 프롬프트, 내부 규칙, 토큰 형식이 새는 문제

AgentShield는 이런 문제를 `공격 -> 판정 -> 개선안 생성 -> 재검증` 흐름으로 연결해, 단순 경고가 아니라 실제 개선에 바로 쓸 수 있는 결과를 만드는 데 초점을 둔다.

## 지금 기준의 제품 정의

현재 1차 제품 목표는 `단일 target URL 기반 검증 + 개선안 생성`이다. 즉 고객은 기본적으로 검사받을 챗봇 URL 하나와 필요 시 API key만 제공하면 되고, AgentShield가 내부에서 공격, 판정, 방어 응답 생성, 재검증, 보고서 구성을 수행한다.

다만 이 프로젝트를 단순 1회성 스캔 도구로만 보면 안 된다. 현재 제품 경험은 `URL 기준 스캔`으로 시작하지만, 내부적으로는 성공 공격 축적, 수동 검수, Chroma 재적재, cleaned export, 파인튜닝으로 이어지는 지속 개선형 플랫폼을 지향한다.

여기서 중요한 해석 기준은 다음과 같다.

- Blue Agent의 1차 산출물은 `방어 응답(defended response)` 이다.
- 방어 코드나 정책은 필요할 때 함께 제안하는 보조 산출물이다.
- 상시 런타임 차단 프록시는 장기 방향이지만, 현재 MVP의 핵심은 `검증과 개선안 제시`다.

## 저장소에 포함된 주요 구성

### 기능 A. 보안 테스트 파이프라인

- 공격 자산을 기준으로 타깃에 실제 입력을 보낸다.
- Judge가 취약 여부를 판정한다.
- Red Agent가 우회 공격을 만들어 다시 시도한다.
- Blue Agent가 더 안전한 방어 응답을 만든다.
- Verify 계층이 같은 공격으로 다시 확인한다.
- 결과는 Dashboard와 Report API에서 조회할 수 있게 저장한다.

여기서 Dashboard는 두 층으로 나뉜다.

- 고객 또는 일반 운영자가 보는 층: scan 시작, 상태, 결과 요약, 방어 응답 비교
- 내부 운영/검수 담당이 보는 층: review queue 수정, Chroma 삭제/재적재, defense 승인

즉 review queue 수정이나 Chroma 관리 UI는 고객사 일반 사용자 화면이 아니라 내부 운영자 도구에 가깝다.

### 기능 B. 직원 AI 모니터링 프록시

- 직원 요청을 정책 기준으로 검사한다.
- 허용된 요청만 실제 타깃 AI로 전달한다.
- 응답을 마스킹하고 usage log, violation record를 남긴다.

### Testbed

- 실제 DB, KB, Tool Gateway가 연결된 테스트용 챗봇 환경이다.
- mock-only 데모가 아니라, 개인정보 조회, 내부 문서 검색, 도구 오남용 같은 시나리오를 실제처럼 재현하기 위한 내부 기준 환경이다.
- 기본 테스트 URL은 `http://localhost:8010/chat` 이다.

## 핵심 특징

- 단일 URL 기반 검증: 고객은 복잡한 내부 포맷을 직접 맞추지 않아도 된다.
- 멀티에이전트 구조: Red, Judge, Blue, Verify가 역할을 나눠 한 흐름을 만든다.
- 실제형 testbed: DB/KB/도구가 연결된 타깃으로 공격을 재현할 수 있다.
- 결과 축적: 세션, 결과, 수동 검토 대상, 위반 로그를 DB에 남긴다.
- 개선안 생성: 취약 응답을 단순 표시하는 데서 끝나지 않고 방어 응답 초안을 만든다.

## 현재 구조를 한눈에 보면

```text
고객 URL 입력
  -> Scan API
  -> Phase 1 대량 공격
  -> Phase 2 우회 공격
  -> Phase 3 방어 응답 생성
  -> Phase 4 재검증
  -> 결과 저장 / 보고서 / 대시보드

직원 AI 요청
  -> Monitoring Proxy
  -> 정책 검사
  -> 허용 요청만 타깃 AI 전달
  -> 마스킹 / 로그 / 위반 저장
```

## 저장소 구조

```text
AgentShield
├── adapters/               # LoRA adapter 실험 자산, 모델별 산출물
├── backend/
│   ├── agents/             # Red/Blue/Judge LLM prompt 및 호출 래퍼
│   ├── api/                # FastAPI 엔드포인트, Dashboard/외부 연동 진입점
│   ├── core/               # Phase 1~4, judge, mutation, 공통 adapter
│   ├── graph/              # LangGraph 기반 전체 오케스트레이션
│   ├── models/             # ORM 모델
│   ├── rag/                # ChromaDB 검색/적재
│   └── report/             # 리포트 생성/요약 산출물
├── dashboard/              # Next.js 대시보드
├── data/                   # 공격/방어 패턴, 학습용 데이터, phase 산출물
├── database/               # PostgreSQL schema, testbed schema
├── defense_proxy/          # 방어 코드 적용 후 재검증 프록시
├── monitoring_proxy/       # 직원 AI 사용 모니터링 프록시
├── testbed/                # 실제 타겟 챗봇, tool gateway, KB, 시드 스크립트
├── chromadb_data/          # 로컬 Chroma persist 디렉터리
└── results/                # 파이프라인 실행 결과 JSON/TXT
```

## 빠르게 이해해야 할 현재 상태

- 기능 A는 `고객 타깃 URL 검증 + 개선안 제시` 방향으로 정리돼 있다.
- 기능 B는 `직원 AI 사용 통제` 경로로 분리돼 있다.
- testbed는 기능 B 본체가 아니라, 기능 A를 재현하고 검증하는 공통 공격 타깃이다.
- 공격 데이터 기준본은 파일이 아니라 PostgreSQL `attack_patterns` 테이블이다.
- 결과 DB는 원본 기록 저장소이고, 학습 데이터는 `backend/data_cleaning/` 정제 export를 기준으로 본다.
- 저장소 기본값은 공유형이 아니라 로컬형이다. PostgreSQL 기본값은 `localhost:5432/agentshield`, Chroma 기본값은 `./chromadb_data` 다.
- 팀이 같은 DB/Chroma를 보려면 공용 운영 모드로 따로 전환해야 한다. 기준은 [TEAM_SHARED_OPS.md](/Users/parkyeonggon/Projects/final_project/AgentShield/TEAM_SHARED_OPS.md) 와 [.env.shared.example](/Users/parkyeonggon/Projects/final_project/AgentShield/.env.shared.example) 를 따른다.

## 개발 및 검증 참고 문서

- [AgentShield_개요.md](/Users/parkyeonggon/Projects/final_project/AgentShield/AgentShield_개요.md): 팀 내부용 제품 방향, 처음 목표와 현재 목표, 기술 스택 정리
- [AgentShield_세부기획서.md](/Users/parkyeonggon/Projects/final_project/AgentShield/AgentShield_세부기획서.md): 전체 파이프라인, 인터페이스, 폴더/파일 구조, 내부 운영 기준
- [AgentShield_기능별_파이프라인.md](/Users/parkyeonggon/Projects/final_project/AgentShield/AgentShield_기능별_파이프라인.md): 역할별 최종 형태와 충돌 방지 기준
- [TEAM_QA_GUIDE.md](/Users/parkyeonggon/Projects/final_project/AgentShield/TEAM_QA_GUIDE.md): 팀원별 실행, DB 점검, 테스트 절차

## 운영 원칙

- 공통 계약을 바꾸면 README, 개요, 세부기획서, 기능별 문서를 같이 갱신한다.
- 공격 데이터 기준은 개인 파일이 아니라 공용 DB를 우선한다.
- testbed는 데모용 폴더가 아니라 팀 공통 검증 기준 환경이다.
- 결과 DB는 원본 저장소이고, 학습은 cleaned export 기준으로 본다.
