import sys
import time
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.finetuning.train_lora import train_role_adapter

def main():
    # 앞서 만든 SFT 데이터셋 경로
    train_data_path = str(PROJECT_ROOT / "data" / "finetuning" / "judge_train.jsonl")

    # 어댑터(LoRA) 가중치가 저장될 경로
    output_model_path = str(PROJECT_ROOT / "adapters" / "lora-judge")

    print("[AgentShield] Judge 모델 파인튜닝 파이프라인을 시작합니다...")

    train_role_adapter(
        role="judge",
        train_file=train_data_path,
        output_dir=output_model_path
    )

if __name__ == "__main__":
    main()