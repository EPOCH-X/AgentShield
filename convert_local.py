import os
import sys
import subprocess

# ==========================================
# 내 PC 환경에 맞게 아래 경로 3곳을 수정하세요
# ==========================================

# 1. 방금 터미널에서 git clone으로 다운받은 llama.cpp 폴더 경로
LLAMA_CPP_DIR = "./llama.cpp"

# 2. 구글 드라이브에서 다운로드하여 압축을 푼 final_adapter 폴더 경로
ADAPTER_DIR = "./final_adapter"

# 3. 변환된 GGUF 파일이 저장될 경로와 파일명
OUTPUT_GGUF_PATH = "./gguf/judge_model_f16.gguf"

# ==========================================

def convert_lora_locally(llama_dir, adapter_dir, output_path):
    # 스크립트 파일 경로 조합
    script_path = os.path.join(llama_dir, "convert_lora_to_gguf.py")
    
    # 경로 검증
    if not os.path.exists(script_path):
        print(f"[오류] 변환 스크립트를 찾을 수 없습니다: {script_path}")
        return
        
    if not os.path.exists(adapter_dir):
        print(f"[오류] 다운로드한 어댑터 폴더를 찾을 수 없습니다: {adapter_dir}")
        return
        
    # 출력될 폴더가 없다면 생성
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # 실행할 터미널 명령어 구성
    cmd = [
        sys.executable,  # 현재 실행 중인 파이썬 인터프리터 (python)
        script_path,
        adapter_dir,
        "--outfile", output_path
    ]
    
    print(f"로컬 PC에서 LoRA 어댑터 GGUF 변환을 시작합니다...")
    print(f"대상 폴더: {adapter_dir}")
    
    try:
        # 터미널 명령어 실행
        subprocess.run(cmd, check=True)
        print(f"\n변환 성공! 파일이 다음 위치에 저장되었습니다:\n{output_path}")
    except subprocess.CalledProcessError as e:
        print(f"\n변환 실패. 에러 내용: {e}")
        print("경로에 한글이 포함되어 있거나 패키지가 부족한지 확인해 주세요.")

if __name__ == "__main__":
    convert_lora_locally(LLAMA_CPP_DIR, ADAPTER_DIR, OUTPUT_GGUF_PATH)