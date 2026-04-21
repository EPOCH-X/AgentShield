# AgentShield

AI 챗봇과 AI 에이전트를 대상으로 보안 테스트를 수행하고, 방어안을 만들고, 실제로 다시 검증하는 플랫폼이다. 이 저장소는 두 축으로 구성된다.

- 기능 A: Find -> Fix -> Verify 보안 테스트 파이프라인
- 기능 B: 직원 AI 사용 모니터링 프록시

## 지금 이 프로젝트가 제공하는 것

- Phase 1: 공격 패턴 기반 대량 스캔
- Phase 2: Red Agent 기반 변형 공격
- Phase 3: Blue Agent 기반 방어 초안 생성
- Phase 4: Defense Proxy 재검증
- Monitoring Proxy: 직원 입력 감시, 정책 위반 탐지, 로그 적재
- Testbed: 실제 DB, KB, Tool Gateway가 연결된 테스트 챗봇

## 현재 상태 요약

### 이미 구현된 것

- `backend/graph/run_pipeline.py`: 로컬 파이프라인 실행기
- `backend/core/phase1_scanner.py`: seed 공격 스캔
- `backend/agents/red_agent.py`: Red Agent 프롬프트 생성기
- `backend/core/phase4_verify.py`: Defense Proxy 기반 재검증
- `monitoring_proxy/monitor_server.py`: 모니터링 프록시 골격과 정책 흐름
- `testbed/`: 실전형 타겟 챗봇 + Tool Gateway + DB/KB 시드

### 아직 미완인 것

- `backend/api/scan.py`: 실제 스캔 API 연결
- `backend/api/report.py`: 보고서 조회 API 고도화
- `backend/api/monitoring.py`: 운영용 모니터링 API 완성
- 공통 target adapter: 고객이 URL/키만 넣어도 붙는 형식 변환 계층

## 핵심 구조

```text
AgentShield
├── backend/
│   ├── core/        # phase1~4, judge, mutation
│   ├── agents/      # red/blue/judge llm prompt logic
│   ├── graph/       # 파이프라인 오케스트레이션
│   ├── api/         # FastAPI 엔드포인트
│   └── rag/         # ChromaDB 연동
├── defense_proxy/   # 방어 재검증 프록시
├── monitoring_proxy/# 직원 AI 사용 감시 프록시
├── testbed/         # 타겟 챗봇 + Tool Gateway
├── database/        # SQL 스키마
├── data/            # 공격/방어/학습 데이터
└── dashboard/       # Next.js 대시보드
```

## 팀이 봐야 하는 문서 순서

1. `AgentShield_개요.md`
2. `AgentShield_세부기획서.md`
3. `AgentShield_기능별_파이프라인.md`
4. `실전형_테스트_챗봇_구축_가이드.md`
5. `TEAM_QA_GUIDE.md`

## 빠른 실행

### 1. Python 환경

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. 기본 백엔드

```bash
cp .env.example .env
python -m backend.dev_seed
uvicorn backend.main:app --reload
```

### 3. Testbed

```bash
python scripts/seed_testbed.py
python scripts/ingest_testbed_kb.py
uvicorn testbed.tool_gateway.app:app --port 8020 --reload
uvicorn testbed.target_chatbot.app:app --port 8010 --reload
```

### 4. 로컬 파이프라인 실행

```bash
python -m backend.graph.run_pipeline --target http://localhost:8010/chat
```

## 운영 원칙

- 문서는 길이보다 역할 분리가 중요하다.
- 구현 상태와 목표 상태를 섞어 쓰지 않는다.
- 고객 통합 구조는 결국 공통 adapter 계층으로 수렴해야 한다.
- testbed는 데모용이 아니라 LLM01, LLM02, LLM06, LLM07을 함께 드러내는 검증 환경이어야 한다.
