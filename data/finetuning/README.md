# 파인튜닝 데이터

이 폴더는 LoRA 학습용 산출물을 둔다.

## 기본 파일

- `red_train.jsonl`
- `judge_train.jsonl`
- `blue_train.jsonl`

## 운영 원칙

- 원본 데이터와 정제 데이터는 분리한다.
- 학습셋 생성 과정은 재현 가능해야 한다.
- 세션 오염 여부를 확인한 뒤 export한다.
