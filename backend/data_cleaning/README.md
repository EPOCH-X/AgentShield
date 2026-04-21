# Data Cleaning

PostgreSQL 원본 수집 데이터는 그대로 두고, 학습용 추출 전에만 정제 규칙을 적용하는 폴더다.

## 목적

- 수집 원본과 학습셋을 분리한다.
- 과거 오염 세션과 제외 행을 재현 가능하게 다시 뽑는다.
- 팀원 `backend/finetuning` 기본 코드와 독립적으로 실행한다.

## 파일

- `cleaning_rules.py`: 공용 정제 규칙
- `audit_training_data.py`: 오염 세션 요약 + 학습 제외 행 목록 생성
- `export_clean_finetuning_data.py`: 정제된 Red/Judge 학습셋 생성
- `export_clean_dpo_data.py`: 정제된 DPO 학습셋 생성

## 실행

AgentShield 루트에서 실행:

```bash
python -m backend.data_cleaning.audit_training_data
python -m backend.data_cleaning.export_clean_finetuning_data
python -m backend.data_cleaning.export_clean_dpo_data --source db --session all
```

## 출력

- `results/training_exclusion_audit_latest.json`
- `results/training_exclusion_rows_latest.jsonl`
- `data/finetuning/cleaned/red_train.jsonl`
- `data/finetuning/cleaned/red_preference_train.jsonl`
- `data/finetuning/cleaned/judge_train.jsonl`
- `data/finetuning/cleaned/dpo_red_train.jsonl`
- `data/finetuning/cleaned/dpo_red_test.jsonl`

## 현재 제외 규칙

- `judgment` 비어 있음
- 학습 대상이 아닌 `judgment` 값
- `attack_prompt` 비어 있음
- `target_response` 비어 있음
- `category` 비어 있음 또는 허용 범위 밖
- `vulnerable`인데 실제 응답이 refusal
- `vulnerable`인데 실제 응답이 meta-analysis

## 운영 원칙

- 원본 DB 행은 여기서 수정하거나 삭제하지 않는다.
- 파인튜닝용 산출물만 별도 경로에 다시 만든다.
- 새 파이프라인 런이 쌓이면 정제 스크립트를 다시 실행한다.