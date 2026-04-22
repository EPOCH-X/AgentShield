# Team Shared Ops

이 문서는 팀원이 같은 PostgreSQL과 같은 Chroma 성공사례 저장소를 보도록 맞출 때 필요한 최소 운영 기준만 정리한다.

## 1. 현재 기본 상태

- 저장소 기본값은 공유형이 아니라 로컬형이다.
- PostgreSQL 기본값은 `localhost:5432/agentshield` 다.
- Chroma 기본값은 `./chromadb_data` 다.
- 따라서 별도 조치를 하지 않으면 파이프라인 결과와 성공사례는 각자 PC에만 쌓인다.

## 2. 공유형으로 바꾸는 기준

- R7이 공용 PostgreSQL 접속 정보와 계정을 배포한다.
- R7이 공용 Chroma 운영 방식을 정한다.
- 팀원 전원은 `.env.shared.example` 기반 공용 `.env` 를 사용한다.
- 파이프라인 실행 호스트와 검수 호스트가 같은 PostgreSQL / Chroma를 바라보는지 먼저 확인한다.

## 3. 운영 역할

- R7: 공용 DB 주소, 계정, 백업/복구 정책, API 배포 담당
- 검수 담당: `review-queue` 조회 후 결과 판정 수정
- R4/R1: Chroma 성공사례 삭제/재적재 기준 관리

## 4. 수동 검수 워크플로

1. 스캔 시작: `POST /api/v1/scan/llm-security`
2. review queue 조회: `GET /api/v1/scan/<session_id>/review-queue`
3. 원문 확인: `GET /api/v1/scan/<session_id>/results/<result_id>`
4. 판정 수정: `PATCH /api/v1/scan/<session_id>/results/<result_id>/review`
5. 방어 코드 승인: 같은 review API에서 `defense_reviewed=true`
6. Chroma 정리: `/api/v1/vector/attack-results`, `/delete`, `/reingest`

## 5. Chroma 관리 API

조회:

```bash
curl -s http://localhost:8000/api/v1/vector/attack-results?limit=10 \
  -H "Authorization: Bearer $TOKEN"
```

삭제:

```bash
curl -s -X POST http://localhost:8000/api/v1/vector/attack-results/delete \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"ids":["<doc_id>"],"seed_ids":[]}'
```

재적재:

```bash
curl -s -X POST http://localhost:8000/api/v1/vector/attack-results/reingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"result_ids":[13604],"delete_existing_seed":true}'
```

## 6. 주의

- Chroma 재적재 전에 PostgreSQL `judgment`, `detail`, `manual_review_needed` 를 먼저 고친다.
- `manual_review_needed=true` 인 상태를 그대로 학습/성공사례로 재적재하지 않는다.
- 공유형으로 전환하지 않은 상태에서 팀원끼리 결과 숫자를 비교하면 서로 다른 DB를 보고 있을 가능성이 높다.