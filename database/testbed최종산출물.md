최종 산출물 (DB 역할 완료)

database/
└── testbed_schema.sql ← 테스트베드 DB 스키마 (7개 테이블)

scripts/
├── seed_testbed.py ← mock 데이터 생성 스크립트
└── ingest_testbed_kb.py ← ChromaDB 적재 스크립트

data/testbed_kb/
├── public/
│ ├── faq.md
│ ├── shipping_policy.md
│ └── refund_policy.md
├── internal/
│ ├── agent_runbook.md
│ └── escalation_guide.md
└── poisoned/
├── injection_direct.md
├── injection_indirect.md
├── injection_encoded.md
└── injection_multilingual.md

---

팀원과 맞춰야 하는 것

팀원 역할 (챗봇 + Tool Gateway) 담당자에게 전달

┌────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 항목 │ 내용 │
├────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ │ customer_db.query, customer_db.update, customer_db.delete, email.send, internal_api.call, │
│ 툴 이름 │ billing.process_refund, auth.reset_password, file_storage.read, file_storage.write, │
│ │ system.execute_command — 절대 변경 금지 │
├────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ DB 접속 │ postgresql://agentshield:agentshield@localhost:5432/agentshield │
├────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ ChromaDB │ kb_public_docs, kb_internal_runbooks, kb_poisoned_docs │
│ 컬렉션 │ │
├────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 이메일 │ email_outbox 테이블에 저장할 것 │
│ 발송 기록 │ │
├────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 모든 툴 │ audit_logs 테이블에 저장할 것 │
│ 호출 기록 │ │
└────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────┘

QA 팀원에게 전달

# 실행 순서

docker-compose up -d db chromadb
psql -h localhost -U agentshield -d agentshield -f database/testbed_schema.sql
python scripts/seed_testbed.py
python scripts/ingest_testbed_kb.py

검증 기준:
customers: 110명
orders: 320건
support_tickets: 160건 (internal_note 20건 포함)
password_reset_requests: 20건
refund_requests: 35건
audit_logs: 50건
ChromaDB: 3개 컬렉션, 총 9개 문서
