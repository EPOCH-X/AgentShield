# 팀원 병합용 — Testbed 로컬 QA 가이드

이 문서는 `AgentShield/testbed/` 실전형 테스트 챗봇을 **각자 PC(로컬 PostgreSQL)** 환경에서 동일하게 실행/검증(QA)하기 위한 안내서입니다.

핵심 원칙은 **환경변수 `TESTBED_DB_URL` 하나로 DB 연결을 통일**하는 것입니다.

---

## 1) 사전 준비

- **Python 3.11+**
- **Ollama 설치**
- **PostgreSQL 설치(로컬)**
- (선택) **pgAdmin** / **DBeaver** 같은 DB GUI

---

## 2) 공통 환경변수(팀원마다 “자기 DB”에 맞게)

### 2.1 `TESTBED_DB_URL` (필수)

형식:

```text
postgresql://USER:PASSWORD@HOST:PORT/DBNAME
```

예시:

```powershell
$env:TESTBED_DB_URL="postgresql://postgres:비밀번호@localhost:5432/postgres"
```

### 2.2 기타(선택)

```powershell
$env:OLLAMA_BASE_URL="http://localhost:11434"
$env:OLLAMA_MODEL="gemma4:e2b"
$env:TOOL_GATEWAY_URL="http://localhost:8020"
$env:TESTBED_SECURITY_MODE="weak"   # 또는 strict
```

---

## 3) 설치(최초 1회)

프로젝트 루트에서:

```powershell
cd "C:\Users\user\Desktop\파이널 프로젝트\agent1\AgentShield"
python -m venv venv
.\venv\Scripts\activate
pip install -U pip
pip install -r requirements.txt
```

> 최신 `scripts/seed_testbed.py`는 `asyncpg`를 사용합니다(보통 `requirements.txt`에 포함).

---

## 4) DB 스키마/시드(최초 1회, 또는 데이터가 비었을 때)

### 4.1 스키마 적용

```powershell
$env:TESTBED_DB_URL="postgresql://postgres:비밀번호@localhost:5432/postgres"
$env:PGCLIENTENCODING="UTF8"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -d "$env:TESTBED_DB_URL" -v ON_ERROR_STOP=1 -f "database\testbed_schema.sql"
```

> `database/testbed_schema.sql`은 안전하게 재실행 가능하도록 **테스트베드 테이블만 DROP 후 재생성**합니다.

### 4.2 시드 주입(더미 데이터 생성)

```powershell
$env:TESTBED_DB_URL="postgresql://postgres:비밀번호@localhost:5432/postgres"
python scripts\seed_testbed.py
```

기대 건수:
- `customers`: 110
- `orders`: 320
- `support_tickets`: 160
- `refund_requests`: 35
- `password_reset_requests`: 20
- `audit_logs`: 50

---

## 5) 서비스 실행(터미널 2개)

### 5.1 Tool Gateway (8020)

```powershell
cd "C:\Users\user\Desktop\파이널 프로젝트\agent1\AgentShield"
.\venv\Scripts\activate
$env:TESTBED_DB_URL="postgresql://postgres:비밀번호@localhost:5432/postgres"
uvicorn testbed.tool_gateway.app:app --port 8020 --reload
```

확인: `http://localhost:8020/health` 에서 `db_connected: true`

### 5.2 Target Chatbot (8010)

```powershell
cd "C:\Users\user\Desktop\파이널 프로젝트\agent1\AgentShield"
.\venv\Scripts\activate
$env:TOOL_GATEWAY_URL="http://localhost:8020"
$env:TESTBED_SECURITY_MODE="weak"
uvicorn testbed.target_chatbot.app:app --port 8010 --reload
```

확인: `http://localhost:8010/health`

---

## 6) 브라우저로 채팅 테스트(UI)

파일: `testbed/chatbot_test.html`

- 브라우저로 열기(더블클릭 또는 Live Server)
- 하단 **서버** 입력칸에는 **`http://localhost:8010` 만** 넣기
  - `/chat`까지 붙이면 내부에서 또 `/chat`을 붙여 **`/chat/chat`** 이 되어 동작이 이상해질 수 있음

---

## 7) QA 스모크 테스트(최소)

### 7.1 health
- `GET http://localhost:8010/health`
- `GET http://localhost:8020/health`

### 7.2 `/chat` 최소 호출(curl)

```powershell
curl -X POST http://localhost:8010/chat -H "Content-Type: application/json" -d "{\"messages\":[{\"role\":\"user\",\"content\":\"CUST-0001 고객 정보 알려줘\"}]}"
```

응답 JSON에 **`content`**가 있으면 API 계약 충족. `tool_trace`에 `customer_db.query`가 찍히면 DB 연동까지 정상.

---

## 8) DB 데이터 “직접 확인”(pgAdmin / psql)

### 8.1 psql로 빠른 확인

```powershell
$env:TESTBED_DB_URL="postgresql://postgres:비밀번호@localhost:5432/postgres"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -d "$env:TESTBED_DB_URL" -c "select count(*) from customers;"
```

### 8.2 pgAdmin에서 행 보기

- `Databases` → (DBNAME 예: `postgres`)
- `Schemas` → `public` → `Tables`
- 테이블 우클릭 → **View/Edit Data → All Rows**

> 최신 스키마/시드는 `audit_logs`도 **초기 50건**을 넣습니다(정상 호출 이력 샘플).

---

## 9) 자주 겪는 문제(해결)

### 9.1 psql 스키마 적용 시 “UHC/UTF8 인코딩 오류”
- 원인: Windows 환경에서 psql이 파일을 CP949(UHC)로 읽어 한글 주석이 깨짐
- 해결: 스키마 적용 전에 `PGCLIENTENCODING="UTF8"` 설정 + `-v ON_ERROR_STOP=1` 사용

### 9.2 pgAdmin에서 테이블은 보이는데 “데이터가 안 보임”
- `View/Edit Data` 후 **Execute(▶) / F5**를 눌러 실행
- 아래 `Data Output` 그리드가 접혀있을 수 있으니 분할바를 내려서 확인
- `SELECT count(*) FROM public.customers;`로 0/110 확인

### 9.3 `chatbot_test.html`에서 아무 반응 없음
- 서버 입력칸은 **`http://localhost:8010`** (끝에 `/chat` 금지)
- `http://localhost:8010/health`가 먼저 뜨는지 확인

### 9.4 시드 실행이 DB에 안 들어가는 것 같을 때
- `TESTBED_DB_URL`이 올바른지 확인(호스트/포트/DB/계정)
- 확인 쿼리:

```sql
SELECT count(*) FROM customers;
```

