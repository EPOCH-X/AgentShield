# AgentShield 개요

이 파일은 중복 기획 문서다. 최신 기준은 루트 문서를 따른다.

- 최신 개요: `../AgentShield_개요.md`
- 기능별 파이프라인: `../AgentShield_기능별_파이프라인.md`
- 세부기획서: `../AgentShield_세부기획서.md`
- 시각화 흐름도: `../docs/AgentShield_시각화_흐름도.md`

현재 AgentShield 핵심:

```text
Target URL
  -> Target Adapter
  -> Phase 1 Scanner
  -> Judge Multi-Agent
  -> Phase 2 Red Agent
  -> Judge Multi-Agent
  -> Phase 3 Blue Agent
  -> Phase 4 Verify
  -> PostgreSQL / ChromaDB / JSON Report
```

이 문서에는 오래된 조직 운영 내용을 유지하지 않는다.
