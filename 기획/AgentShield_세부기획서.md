# AgentShield 세부기획서

이 파일은 중복 기획 문서다. 최신 기준은 루트 문서를 따른다.

- 최신 세부기획서: `../AgentShield_세부기획서.md`
- 최신 Judge 기준: `../LLM_Judge_분석_및_업계동향.md`
- 최신 결과 기록: `../최신_결과_및_변경사항.md`

현재 핵심 설계:

- Target Adapter로 URL/provider 계약을 통일한다.
- Judge는 Evidence Scanner, Strict Auditor, Context Auditor, Final Judge 구조다.
- Phase 4는 `defended_response_only` 검증을 기본으로 한다.
- Red Adaptive Campaign은 DB/Chroma 저장 없이 공격을 수확하고 `success_only`만 replay 후보로 둔다.

이 문서에는 오래된 조직 운영 내용을 유지하지 않는다.
