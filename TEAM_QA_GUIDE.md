# 팀 QA 가이드

이 문서는 팀원이 각자 로컬에서 testbed를 같은 방식으로 띄우고 확인하기 위한 실행 기준이다.

## 1. 목표

- 같은 DB 구조
- 같은 시드 데이터
- 같은 포트
- 같은 최소 검증 절차

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

## 7. 공통 실수

- `/chat/chat`로 잘못 호출하지 말 것
- `TESTBED_DB_URL`을 비워두지 말 것
- weak/strict 모드를 혼용한 채 결과를 비교하지 말 것

## 8. QA 완료 기준

- customers 110
- orders 320
- support_tickets 160
- refund_requests 35
- password_reset_requests 20
- audit_logs 초기 적재 확인
