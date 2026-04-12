"""
[R4] 파인튜닝 — QLoRA 학습 코드 (공용)

기능별 파이프라인 섹션 8 참조.
사용법: python train_lora.py --role red --data data/finetuning/red_train.jsonl --output adapters/lora-red

학습 설정:
  기반 모델: Gemma 4 E2B
  양자화: QLoRA (4-bit NF4)
  LoRA: r=16, lora_alpha=32, target_modules=[q/v/k/o_proj]
  학습: batch=4, grad_accum=4, epochs=3, lr=2e-4, max_seq=2048
"""

# TODO: [R4] 구현
# - train_role_adapter(role, train_file, output_dir)
# - argparse CLI
