# AgentShield

> AI Agent 보안 테스트 + 직원 AI 사용 모니터링 플랫폼

AgentShield는 기존 도구들처럼 "방어만" 하거나 "발견만" 하는 한계를 넘어, Find(발견) → Fix(방어 코드 생성) → Verify(실제 검증) 과정을 단일 파이프라인으로 자동화한 프로젝트입니다. 프롬프트 인젝션, 민감정보 유출 등 OWASP LLM Top 10의 핵심 위협으로부터 기업의 AI 에이전트를 안전하게 보호하고, 내부 직원의 AI 사용을 모니터링합니다.

## 프로젝트 구조

```
AgentShield/
├── backend/
│   ├── api/
│   │   ├── auth.py               # [R7] JWT 인증
│   │   ├── scan.py               # [R7] 스캔 API
│   │   ├── report.py             # [R7] 보고서 API
│   │   └── monitoring.py         # [R7] 모니터링 API
│   ├── models/
│   │   ├── attack_pattern.py     # [R2] 공격 패턴 모델
│   │   ├── test_session.py       # [R7] 테스트 세션 모델
│   │   ├── test_result.py        # [R7] 테스트 결과 모델
│   │   ├── employee.py           # [R5] 직원 모델
│   │   ├── usage_log.py          # [R5] 사용 로그 모델
│   │   ├── violation.py          # [R5] 위반 모델
│   │   └── policy_rule.py        # [R5] 정책 규칙 모델
│   ├── core/
│   │   ├── phase1_scanner.py     # [R2] 정적 스캐너
│   │   ├── phase2_red_agent.py   # [R1] Red Agent 공격
│   │   ├── phase3_blue_agent.py  # [R3] Blue Agent 방어
│   │   ├── phase4_verify.py      # [R3] 방어 검증
│   │   └── judge.py              # [R1] 판정 로직
│   ├── agents/
│   │   ├── llm_client.py         # [R4] Ollama LLM 클라이언트
│   │   ├── red_agent.py          # [R1] Red Agent
│   │   ├── blue_agent.py         # [R3] Blue Agent
│   │   └── judge_agent.py        # [R1] Judge Agent
│   ├── rag/
│   │   ├── chromadb_client.py    # [R4] ChromaDB 연결
│   │   ├── embedder.py           # [R4] 임베딩 생성
│   │   └── ingest.py             # [R4] 데이터 수집
│   ├── graph/
│   │   └── llm_security_graph.py # [R1] LangGraph 오케스트레이션
│   ├── report/
│   │   ├── generator.py          # [R7] 보고서 생성
│   │   └── templates/
│   │       └── security_report.html  # [R7] 보고서 템플릿
│   ├── finetuning/
│   │   ├── prepare_data.py       # [R4] 학습 데이터 전처리
│   │   ├── train_lora.py         # [R4] QLoRA 학습
│   │   └── merge_adapter.py      # [R4] 어댑터 병합
│   ├── config.py                 # [R7] 환경 설정
│   ├── database.py               # [R7] DB 연결
│   └── main.py                   # [R7] FastAPI 엔트리포인트
│
├── dashboard/                    # [R6] 프론트엔드 전체
│   ├── app/
│   │   ├── layout.tsx            # [R6] 공통 레이아웃
│   │   ├── page.tsx              # [R6] 랜딩 페이지
│   │   ├── login/page.tsx        # [R6] 로그인
│   │   ├── scan/page.tsx         # [R6] 스캔 시작
│   │   ├── scan/[id]/page.tsx    # [R6] 스캔 결과
│   │   ├── monitoring/page.tsx   # [R6] 모니터링
│   │   ├── monitoring/admin/page.tsx  # [R6] 관리자 설정
│   │   └── report/[id]/page.tsx  # [R6] 보고서 뷰어
│   ├── components/
│   │   ├── VulnerabilityMap.tsx   # [R6] 취약점 맵
│   │   ├── ScanProgress.tsx      # [R6] 스캔 진행률
│   │   ├── DefenseCodeViewer.tsx  # [R6] 방어 코드 뷰어
│   │   ├── BeforeAfterCompare.tsx # [R6] 전후 비교
│   │   └── MonitoringDashboard.tsx # [R6] 모니터링 대시보드
│   └── mocks/
│       └── mockData.ts           # [R6] Mock 데이터
│
├── defense_proxy/
│   └── proxy_server.py           # [R3] 방어 프록시 서버
│
├── monitoring_proxy/
│   └── monitor_server.py         # [R5] 모니터링 프록시 서버
│
├── data/
│   ├── attack_patterns/          # [R2] 공격 패턴 데이터
│   ├── defense_patterns/         # [R3] 방어 패턴 데이터
│   └── finetuning/               # [R4] 학습 데이터
│
├── adapters/
│   ├── lora-red/                 # [R1] Red Agent 어댑터
│   ├── lora-judge/               # [R1] Judge 어댑터
│   └── lora-blue/                # [R3] Blue Agent 어댑터
│
├── docker-compose.yml            # [R7] 컨테이너 구성
├── Dockerfile                    # [R7] 빌드 설정
├── requirements.txt              # [R7] Python 의존성
└── .env.example                  # [R7] 환경 변수 템플릿
```

## 기술 스택

| 계층          | 기술                                               |
| ------------- | -------------------------------------------------- |
| LLM           | Gemma 4 E2B (2.3B effective / 5.1B PLE) via Ollama |
| Backend       | FastAPI + async SQLAlchemy + PostgreSQL 16         |
| RAG           | ChromaDB + all-MiniLM-L6-v2 (384d)                 |
| Orchestration | LangGraph StateGraph                               |
| Fine-tuning   | QLoRA 4-bit NF4, r=16, lora_alpha=32               |
| Frontend      | Next.js 14 (App Router) + Chart.js                 |
| Infra         | Docker Compose                                     |

## 로컬 실행

```bash
# 1. 환경 변수 설정
cp .env.example .env

# 2. 컨테이너 기동
docker-compose up -d

# 3. 프론트엔드 (별도 터미널)
cd dashboard
npm install
npm run dev
```

## 담당자 가이드

각 파일 상단에 `[R1]`~`[R7]` 태그로 담당자가 표시되어 있습니다.
`TODO:` 검색으로 자신의 담당 영역을 확인하세요.

```bash
# 자기 담당 TODO 검색 예시 (R1)
grep -rn "TODO.*\[R1\]" backend/
```

| 역할 | 담당 영역                                                  |
| ---- | ---------------------------------------------------------- |
| R1   | Red Agent, Judge, LangGraph 오케스트레이션, LoRA-Red/Judge |
| R2   | Phase 1 정적 스캐너, 공격 패턴 DB, OWASP 분류              |
| R3   | Blue Agent, Defense Proxy, Phase 3-4, LoRA-Blue            |
| R4   | RAG 파이프라인, Ollama 통합, QLoRA 학습 코드               |
| R5   | Monitoring Proxy, 정책 엔진, 위반 탐지                     |
| R6   | Next.js 대시보드 (프론트엔드 전체)                         |
| R7   | 보고서 생성, DB 스키마, API 통합                           |
