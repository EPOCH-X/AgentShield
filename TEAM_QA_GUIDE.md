# 팀 QA 가이드

이 문서는 팀원이 각자 로컬에서 testbed를 같은 방식으로 띄우고 확인하기 위한 실행 기준이다.

## 1. 목표

- 같은 DB 구조
- 같은 시드 데이터
- 같은 포트
- 같은 최소 검증 절차
- 고객이 target URL 하나만 넣고도 검증할 수 있는 환경 재현

## 2. 필수 환경변수

- `TESTBED_DB_URL`
- `TOOL_GATEWAY_URL`
- `TESTBED_SECURITY_MODE`
- `OLLAMA_BASE_URL`
- `OLLAMA_MODEL`

예시:

```bash
export TESTBED_DB_URL="postgresql://postgres:password@localhost:5432/postgres"
export TOOL_GATEWAY_URL="http://localhost:8020"
export TESTBED_SECURITY_MODE="weak"
export OLLAMA_BASE_URL="http://localhost:11434"
export OLLAMA_MODEL="gemma4:e2b"
```

## 3. 최초 1회

```bash
python -m venv venv
source venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## 4. DB 준비

```bash
psql "$TESTBED_DB_URL" -f database/testbed_schema.sql
python scripts/seed_testbed.py
python scripts/ingest_testbed_kb.py
```

빠른 상태 확인:

```bash
nc -z localhost 5433 && echo TESTBED_DB_UP || echo TESTBED_DB_DOWN
psql "$TESTBED_DB_URL" -c "SELECT COUNT(*) AS customers FROM customers;"
psql "$TESTBED_DB_URL" -c "SELECT COUNT(*) AS orders FROM orders;"
psql "$TESTBED_DB_URL" -c "SELECT COUNT(*) AS audit_logs FROM audit_logs;"
```

## 5. 서버 실행

### Tool Gateway

```bash
uvicorn testbed.tool_gateway.app:app --port 8020 --reload
```

### Target Chatbot

```bash
uvicorn testbed.target_chatbot.app:app --port 8010 --reload
```

## 6. 최소 QA

### health

- `GET /health` on 8010
- `GET /health` on 8020

### chat

```bash
curl -X POST http://localhost:8010/chat \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"CUST-0001 고객 정보 알려줘"}]}'
```

확인 항목:

- `content` 존재
- `tool_trace` 또는 audit log 기록
- DB 연결 정상

tool trace 없이 확인할 때:

```bash
psql "$TESTBED_DB_URL" -c "SELECT tool_name, result_summary, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 5;"
```

### AgentShield scan 연결 확인

검증 시스템은 같은 타겟 URL을 내부에서 반복 호출해 원응답과 방어 재검증을 수행한다.

예시 target URL:

- `http://localhost:8010/chat`

핵심 확인:

- 고객이 넘길 값은 target URL 하나면 충분한가
- attack -> target original response -> judge -> blue defense -> rejudge 흐름이 성립하는가

## 7. 공통 실수

- `/chat/chat`로 잘못 호출하지 말 것
- `TESTBED_DB_URL`을 비워두지 말 것
- weak/strict 모드를 혼용한 채 결과를 비교하지 말 것
- shared DB를 바로 학습 데이터셋이라고 생각하지 말 것
- `manual_review_needed`가 걸린 결과를 그대로 export하지 말 것

## 8. DB 오염관리

- `test_results`는 일단 모으는 원본 저장소다. 성공, 실패, 애매한 케이스가 같이 들어와도 된다.
- 사람이 다시 봐야 하는 건 review queue에서 먼저 확인한다.
- `manual_review_needed=true`가 붙은 건 바로 학습에 쓰지 않는다.
- 학습 파일은 항상 `backend/data_cleaning/` 정제 스크립트로 다시 뽑는다.
- 팀 공통 규칙은 하나만 기억하면 된다: `raw는 DB`, `train/eval은 cleaned export`.

## 9. QA 완료 기준

- customers 110
- orders 320
- support_tickets 160
- refund_requests 35
- password_reset_requests 20
- audit_logs 초기 적재 확인
- target URL `http://localhost:8010/chat` 로 실제 질의 가능
