# Data Cleaning

이 폴더는 학습용 export 전에 데이터 오염을 걸러내는 정제 스크립트를 둔다.

## 목적

- 원본 DB 행은 건드리지 않는다.
- 학습 제외 기준을 재현 가능하게 남긴다.
- 파인튜닝용 산출물만 별도 경로에 다시 만든다.

## 주요 스크립트

- `audit_training_data.py`
- `export_clean_finetuning_data.py`
- `export_clean_dpo_data.py`

## 출력

- exclusion audit
- exclusion rows
- cleaned finetuning data

## 원칙

- 결과 비교가 가능한 정제 규칙만 유지한다.
- 오염 발견은 판정 로직 변경보다 먼저 감사 로그로 남긴다.
