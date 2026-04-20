# AgentShield

> AI Agent 보안 테스트 + 직원 AI 사용 모니터링 플랫폼

AgentShield는 기존 도구들처럼 "방어만" 하거나 "발견만" 하는 한계를 넘어, Find(발견) → Fix(방어 코드 생성) → Verify(실제 검증) 과정을 단일 파이프라인으로 자동화한 프로젝트입니다. 프롬프트 인젝션, 민감정보 유출 등 OWASP LLM Top 10의 핵심 위협으로부터 기업의 AI 에이전트를 안전하게 보호하고, 내부 직원의 AI 사용을 모니터링합니다.

기능 B의 Monitoring Proxy는 단순 키워드 차단기가 아니라, 운영 요청을 직접 받는 게이트웨이로서 인증/로깅/사용량 제어를 수행하고, 규칙 기반 1차 필터 이후 애매한 요청에 대해서는 LLM 기반 2차 의도 판정을 수행합니다. 초기 구현은 base 모델을 사용하고, 추후 기능 B 전용 LoRA로 분리할 수 있습니다.

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
│   │   ├── judge.py              # [R1] 판정 로직
│   │   ├── mutation_engine.py    # [R1] 코드 기반 공격 변형 엔진
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
│   │   ├── llm_security_graph.py # [R1] LangGraph 오케스트레이션
│   │   └── run_pipeline.py       # [R1] Phase 1+2 파이프라인 실행기
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
| LLM           | Gemma 4 E2B (타겟) + Gemma 4 26B (Red Agent) via Ollama |
| Guard (L2)    | Qwen 2.5 0.5B — 카테고리별 few-shot Judge           |
| Backend       | FastAPI + async SQLAlchemy + PostgreSQL 16         |
| RAG           | ChromaDB PersistentClient + all-MiniLM-L6-v2 (384d), 유사도 임계값 0.90 |
| Orchestration | LangGraph StateGraph                               |
| Fine-tuning   | DPO (seed_id 기반 chosen/rejected 페어링) + QLoRA 4-bit NF4 |
| Frontend      | Next.js 14 (App Router) + Chart.js                 |
| Infra         | Docker Compose (또는 로컬 Homebrew PostgreSQL)       |

## 현재 구현 상태 (2026-04-16)

### Phase 1 + Phase 2 파이프라인

- **Phase 1**: `data/attack_patterns/colla_v1.json` + `colla_v2.json`에서 160개 seed 로드 → 규칙 기반 대량 스캔
- **Phase 2**: Red Agent (gemma4:26b, REDSTRIKE 페르소나)가 Phase 1 safe 결과를 최대 5라운드 변형 공격
- **Mock Tools (LLM06)**: `backend/core/mock_tools.py` — 10개 시뮬레이션 도구 (query_database, delete_records, send_email 등)
- **seed_id 추적**: 각 seed에 UUID 부여 → Phase 1/2 결과를 seed_id로 연결 → DPO 학습 데이터 페어링

### 3-Layer Judge 시스템

```
응답 수신
    │
    ▼
[Layer 1] 규칙 기반 판정 (카테고리별 전용 로직)
    │  LLM01: 역할 변조 + 거부 문구 / LLM02: PII 정규식 / LLM06: Mock Tool 호출 감지 / LLM07: 시스템 프롬프트 구조
    │  → vulnerable / safe: 즉시 반환
    │  → ambiguous + 거부 응답 감지: Guard bypass → safe (confidence 0.9)
    │  → ambiguous: Layer 2로
    │
    ▼
[Layer 2] Guard Judge (Qwen 2.5 0.5B)
    │  카테고리별 few-shot 프롬프트로 harmful/unharmful 판정
    │  → 결과 채택 (confidence 매핑)
    │
    ▼
[Layer 3] 수동 검토 큐 (현재 미구현 — ambiguous로 마킹)
```

- **FP 방지**: 거부 응답("cannot query", "I cannot delete" 등)에 대해 refusal-first 검사 수행
- **Guard bypass**: L1 ambiguous이면서 거부 응답인 경우, Guard에 넘기지 않고 safe 반환 (Guard 0.5B의 FP 방지)

### DB 통합

- **PostgreSQL 16**: `database/schema.sql` 기반, seed_id/round/subcategory/detail 컬럼 추가
- **DB 저장**: `save_results_to_db()` — 파이프라인 완료 후 TestSession + TestResult 일괄 저장
- **DPO 내보내기**: `python -m backend.finetuning.export_dpo_data --source db --session latest`

### 최신 베이스라인 결과

```
gemma4:26b (정상 모델) → gemma4:e2b, 160 seeds × 5 rounds

전체 취약률: 43.8% (70/160)
  LLM01 (Prompt Injection):      65.0% (26/40)
  LLM02 (Sensitive Info):        40.0% (16/40)
  LLM06 (Excessive Agency):      52.5% (21/40)
  LLM07 (System Prompt Leak):    17.5%  (7/40)

Phase 2가 전체 취약점의 74.3% 발견 — Red Agent 변형 공격이 핵심 가치
DB 저장: 734 records (session 9e1b083e)
```

## 로컬 실행

```bash
# 1. 환경 변수 설정
cp .env.example .env

# 1-1. 모델 준비
ollama pull gemma4:e2b
ollama pull gemma4:26b

# 2. 컨테이너 기동
docker-compose up -d

# 3. 프론트엔드 (별도 터미널)
cd dashboard
npm install
npm run dev
```

Red Agent의 런타임 공격 변형은 기본적으로 `OLLAMA_RED_MODEL=gemma4:26b`를 사용한다. 팀원이 26B를 로컬에 두지 않은 경우에는 `OLLAMA_MODEL=gemma4:e2b` 폴백 경로로 계속 개발/테스트할 수 있다.

### 처음부터 순서대로 (Windows · Docker 없이 · 백엔드+DB만)

**준비물:** Python 3.11 이상, PostgreSQL 설치 완료(서비스가 떠 있어야 함).

**1) PostgreSQL에서 유저·DB 만들기**  
pgAdmin 또는 `psql`을 열고 *postgres* 슈퍼유저로 접속한 뒤 아래를 실행합니다.

```sql
CREATE USER agentshield WITH PASSWORD 'agentshield';
CREATE DATABASE agentshield OWNER agentshield;
```

**주의 — `CREATE USER`를 cmd/ PowerShell에 그대로 치면 안 됩니다.**  
`CREATE`는 Windows 명령이 아니라 **PostgreSQL용 SQL**입니다. 검은 화면(cmd)에 붙여넣으면 `'CREATE'은(는) 내부 또는 외부 명령...` 오류가 납니다.

- **pgAdmin:** 왼쪽에서 서버 연결 → **Tools → Query Tool** → 위 SQL 두 줄 붙여넣기 → 실행(▶).
- **psql:** 시작 메뉴에서 “SQL Shell (psql)” 실행 → 서버/포트/DB는 기본값(Enter) → **User name에 `postgres`** → 비밀번호 입력 후, 프롬프트 `postgres=#`에서 위 SQL 입력 후 세미콜론까지 입력하고 Enter.

또는 PowerShell에서 한 번에 (설치 경로·비번은 본인 환경에 맞게):

```powershell
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -c "CREATE USER agentshield WITH PASSWORD 'agentshield';"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -c "CREATE DATABASE agentshield OWNER agentshield;"
```

**`docker` 명령이 안 될 때:** Docker Desktop이 설치되어 있지 않거나 PATH에 없는 상태입니다. **Docker 없이** 진행하려면 로컬 PostgreSQL만 설치하고 위처럼 `psql`/pgAdmin을 쓰면 됩니다. Docker를 쓰려면 [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/) 설치 후 PC 재시작(또는 터미널 재실행)하세요. `docker compose`는 **`AgentShield` 폴더**(`docker-compose.yml` 있는 곳)에서 실행합니다. 지금 경로가 `...\agent`만 열려 있으면 `cd AgentShield` 후 실행합니다.

**2) 프로젝트 폴더로 이동** (본인 경로에 맞게 수정)

```powershell
cd "C:\Users\user\Desktop\파이널 프로젝트\agent\AgentShield"
```

**3) 가상환경 + 패키지**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

실행 정책 오류가 나면 관리자 PowerShell에서 한 번만:  
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

**4) 환경 변수 파일**

```powershell
Copy-Item .env.example .env
```

`localhost:5432`, 유저/DB `agentshield` 그대로 쓰면 `.env` 수정 없이 진행 가능합니다. 포트·비밀번호를 바꿨다면 `.env`의 `DATABASE_URL`만 고칩니다.

**5) 테이블 생성 + 시드 데이터**

```powershell
python -m backend.dev_seed
```

**6) DB에 잘 붙었는지·행 수 확인**

```powershell
python -m backend.db_inspect
```

**7) API 서버 기동**

```powershell
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

**8) 동작 확인**  
브라우저에서 `http://127.0.0.1:8000/health` → `{"status":"ok"}`  
또는 PowerShell:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
```

로그인·스캔 API는 아직 스텁인 경우가 많으니, 위까지 되면 **DB + 백엔드 골격**은 정상입니다.

---

**Docker로 DB만 쓰고 싶을 때:** Docker Desktop 설치 후 `AgentShield`에서 `docker compose up -d db` → `.env`의 `DATABASE_URL`을 `postgresql+asyncpg://agentshield:agentshield@localhost:5432/agentshield`로 두고, **5)~8)** 을 같은 PowerShell에서 진행하면 됩니다.

### Docker 없이 백엔드 + PostgreSQL만 실행

1. **PostgreSQL**을 설치하고, `.env.example`과 맞는 DB·유저를 만듭니다. (기본값: DB 이름 `agentshield`, 유저/비밀번호 `agentshield`)

   ```sql
   CREATE USER agentshield WITH PASSWORD 'agentshield';
   CREATE DATABASE agentshield OWNER agentshield;
   ```

2. **환경 변수**: `cp .env.example .env` 후 필요 시 `DATABASE_URL`만 본인 환경에 맞게 수정합니다.  
   형식은 반드시 `postgresql+asyncpg://USER:PASSWORD@HOST:PORT/DBNAME` 입니다.

3. **의존성** (저장소 루트 `AgentShield/`에서):

   ```bash
   pip install -r requirements.txt
   ```

4. **서버 기동** — 반드시 `AgentShield/` 디렉터리에서 실행합니다 (`backend` 패키지 기준 경로).

   ```bash
   uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```

   앱이 뜰 때 `lifespan`에서 `init_db()`가 한 번 실행되며, **없는 테이블만** SQLAlchemy `create_all`로 생성됩니다.

#### 테이블 생성 여부 확인

- **API**: 브라우저나 `curl`로 `http://localhost:8000/health` → `{"status":"ok"}` 이면 서버는 기동된 상태입니다. (DB 연결 실패 시 여기까지 안 올라올 수 있으니 터미널 로그를 함께 봅니다.)

- **PostgreSQL**에서 테이블 목록:

  ```bash
  psql -h localhost -U agentshield -d agentshield -c "\dt"
  ```

  다음 7개가 보이면 스키마가 반영된 것입니다:  
  `attack_patterns`, `test_sessions`, `test_results`, `employees`, `usage_logs`, `violations`, `policy_rules`

#### DATABASE_URL 맞추기

- **형식:** `postgresql+asyncpg://사용자:비밀번호@호스트:포트/데이터베이스이름`
- 로컬 기본 예: `postgresql+asyncpg://agentshield:agentshield@localhost:5432/agentshield`
- PostgreSQL을 다른 포트로 띄웠다면 `5432`만 바꿉니다.
- `.env`에만 두면 됩니다. `backend/config.py`가 자동으로 읽습니다.

#### 개발용 초기 데이터(시드)

Phase 1 등에서 테이블을 읽을 최소 데이터를 넣으려면, 테이블 생성 후 **한 번** 실행합니다.

```bash
# AgentShield/ 에서, venv 활성화 후
python -m backend.dev_seed
```

- `attack_patterns`: 카테고리 LLM01/02/06/07 샘플 4건 (`source=seed_dev`)
- `policy_rules`: 정규식 예시 1건
- `employees`: `employee_id=dev-user-001` 테스트 직원 1명

이미 `seed_dev` 패턴이 있으면 다시 넣지 않습니다. 대량 적재는 R2 파이프라인·별도 스크립트로 진행합니다.

팀에 안내할 때는 위 «Docker 없이…» + «DATABASE_URL» + «dev_seed» 세 덩어리를 함께내면 됩니다.

#### 공유 DB에서 “저장되는지” 확인하기

- **같은 데이터를 보려면** 팀 전원의 `.env`에 **동일한 `DATABASE_URL`**이 있어야 합니다.  
  각자 PC에만 PostgreSQL을 깔고 `localhost`로만 붙으면, **본인 DB에만** 쌓이고 서로 안 보입니다.
- **공유하는 방법 예:** 한 대의 서버/클라우드(RDS, Supabase, 팀용 VM 등)에 DB 하나 두고, URL을 `postgresql+asyncpg://...@그서버주소:5432/agentshield` 형태로 공유합니다.

저장·조회가 되는지 빠르게 보려면:

```bash
python -m backend.db_inspect
```

테이블별 **행 개수**가 나옵니다. 누군가 스캔/모니터링으로 데이터를 넣으면 `test_results`, `usage_logs` 등 숫자가 늘어납니다.  
또는 `psql`로 `SELECT COUNT(*) FROM test_results;` 같이 직접 조회해도 됩니다.

### 팀에 DB 스키마만 먼저 줄 때 (세부기획서 §6 그대로)

저장소에 **`database/schema.sql`** 이 있습니다. 기획서와 동일한 DDL입니다.

**R7이 팀에 전달할 순서:**

1. **Git으로 공유:** `database/schema.sql` 이 포함된 브랜치/저장소를 팀원이 `git pull` 한다.
2. **각자(또는 공용 서버에서) PostgreSQL에 DB·유저 준비** — 예: `agentshield` DB, 유저 `agentshield`.
3. **스키마 적용 (한 번만):** `AgentShield` 폴더에서 아래 중 하나 실행.

   ```powershell
   # PostgreSQL bin 경로·비밀번호는 본인 환경에 맞게
   & "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U agentshield -d agentshield -f database/schema.sql
   ```

   `postgres` 슈퍼유저로 `agentshield` DB에 넣을 때:

   ```powershell
   & "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -d agentshield -f database/schema.sql
   ```

4. **`.env`에 `DATABASE_URL`** 동일하게 맞추기.
5. **(선택)** `python -m backend.dev_seed` — 샘플 행만 추가. 스키마는 이미 SQL로 있으므로 **필수는 아님**.
6. **백엔드:** `uvicorn ...` 기동 시 `init_db()`의 `create_all`은 **이미 있는 테이블은 건드리지 않음**.

### Docker DB 초기화/재생성 (팀원 로컬)

`docker compose`로 올린 Postgres는 **처음 볼륨이 생성될 때만** `database/schema.sql`이 자동 적용됩니다. (이미 `pgdata` 볼륨이 있으면 새 스키마가 반영되지 않을 수 있음)

**PowerShell 기준**

```powershell
cd "C:\Users\user\Desktop\파이널 프로젝트\agent\AgentShield"

# DB만 기동 (처음 1회면 schema.sql 자동 실행)
docker compose up -d db

# 스키마 변경 후 "완전 초기화"가 필요하면 (데이터/볼륨 삭제)
docker compose down -v
docker compose up -d db
```

**테이블 생성 확인**

```powershell
docker compose exec db psql -U agentshield -d agentshield -c "\dt"
```

**주의:** 같은 DB에 `schema.sql`을 **두 번** 실행하면 `already exists` 오류가 납니다. 초기화가 필요하면 DB를 드롭 후 재생성하거나, 팀 규칙으로 Alembic 마이그레이션으로 전환합니다.

**ORM과의 관계:** `backend/models/*` 는 이 스키마와 맞춰 두었습니다. 스키마는 **이 SQL 파일이 기준**이면 됩니다.

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
| R5   | Monitoring Proxy, 정책 엔진, 위반 탐지, 2차 LLM 의도 판정 |
| R6   | Next.js 대시보드 (프론트엔드 전체)                         |
| R7   | 보고서 생성, DB 스키마, API 통합                           |
