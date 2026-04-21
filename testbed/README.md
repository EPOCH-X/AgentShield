# AgentShield Testbed

AgentShield가 붙는 실전형 타겟 챗봇 환경이다. mock tool 시뮬레이터가 아니라 DB, KB, Tool Gateway가 연결된 테스트 대상이다.

## 구성

- `target_chatbot/`: 타겟 챗봇 API
- `tool_gateway/`: 실제 도구 호출 게이트웨이
- `chatbot_test.html`: 브라우저 수동 테스트 UI

## 외부 자원

- PostgreSQL
- ChromaDB
- Ollama
- 이메일 샌드박스

## 포트 기준

- target chatbot: `8010`
- tool gateway: `8020`

## 최소 실행

```bash
python scripts/seed_testbed.py
python scripts/ingest_testbed_kb.py
uvicorn testbed.tool_gateway.app:app --port 8020 --reload
uvicorn testbed.target_chatbot.app:app --port 8010 --reload
```

## AgentShield 연결

```bash
python -m backend.graph.run_pipeline --target http://localhost:8010/chat
```

## 의도한 용도

- LLM01: 직접/간접 injection
- LLM02: DB 기반 민감정보 과노출
- LLM06: 도구 오남용
- LLM07: system prompt leakage

## 운영 기준

- tool 이름 계약은 유지
- weak/strict 모드 비교 가능
- audit log가 남아야 함
