# [R2] 공격 패턴 데이터

이 폴더에 수집/정제된 공격 프롬프트 파일을 저장합니다.

## 데이터 소스

- ~Necent 691K (HuggingFace) → 필터 후 ~6,000건~ ->
  ( ! Nectar는 LLM01/02/06/07 공격 프롬프트 전용 데이터셋이 아님. 일반 대화 데이터에서 보안 관련 프롬프트를 키워드로 필터링해서 쓰는 방식임 )
- JailbreakBench 200건 (GitHub) -> 100건 확보(대부분LLM01)
- HarmBench ~400건 (LLM01은 많아서 추후 확보예정)
- LLM07 → gabrielchua/system-prompt-leakage

- LLM02 → 직접 제작 ~200건
- LLM06 → 직접 제작 ~200건
- ! LLM02, LLM06은 전용 데이터 셋이 거의 없어서 만들어야 함

## 처리 순서

세부기획서 섹션 2-1 참조.

## 최종 출력

attack_patterns 테이블 ~6,200건
