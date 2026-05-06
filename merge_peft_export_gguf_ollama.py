#!/usr/bin/env python3
"""
PEFT LoRA를 베이스에 merge → HF 폴더 저장 → (선택) llama.cpp로 GGUF → (선택) Ollama 등록.

================================================================================
[필독] llama.cpp 위치 (이 머신) — AgentShield 레포 내부에 클론하지 말 것.
  --llama-cpp 는 항상 아래 경로(동일 수준 `3. final/llama.cpp`)를 쓴다.
  /Users/parkjoyeong/Desktop/Park Joyeong/Class/Projects/3. final/llama.cpp
  (과거에 AgentShield/.cache/llama.cpp 를 새로 클론해 쓰지 말 것. 혼동·해시 누락만 유발)
================================================================================

로컬 PEFT 추론(USE_LOCAL_PEFT=true)이 Mac에서 느리고 RAM을 많이 쓸 때,
merge된 GGUF를 Ollama로 올리고 USE_LOCAL_PEFT=false + OLLAMA_BLUE_TARGET_MODEL 로 쓰는 용도.

필요: pip에 torch, transformers, peft (학습 환경과 동일 권장)

GGUF 변환 실패 시 (BPE pre-tokenizer was not recognized / chkhsh):
  - llama.cpp 를 최신으로: `cd <llama.cpp> && git pull` (Qwen3.5 텍스트 지원은 최근 커밋에 포함됨)
  - 그래도 안 되면 저장소 안 `convert_hf_to_gguf_update.py` 실행 후 다시 변환 (HF 토큰 필요할 수 있음)
  - 참고: https://github.com/ggml-org/llama.cpp/issues/20116

예시 (프로젝트 루트에서, --llama-cpp 는 위 [필독] 절대 경로):

  # Qwen3.5-2B 어댑터 (기본 출력 adapters/lora-blue-qwen 등)
  python merge_peft_export_gguf_ollama.py ^
  --base-model Qwen/Qwen3.5-2B ^
  --adapter AgentShield/adapter ^
  --merged-hf AgentShield/merged ^
  --llama-cpp C:/Pyg/final_project/AgentShield/llama.cpp ^
  --gguf-out AgentShield/gguf/judge-f16.gguf ^
  --outtype f16

  # HF merge만 (GGUF/Ollama는 llama.cpp 설치 후 --llama-cpp 로 재실행하거나 출력된 명령 수동 실행)
  python scripts/merge_peft_export_gguf_ollama.py \\
    --base-model Qwen/Qwen3.5-2B \\
    --adapter adapters/lora-blue \\
    --merged-hf exports/qwen35-2b-blue-merged-hf

  # GGUF만 이미 있으면 merge 생략
  python scripts/merge_peft_export_gguf_ollama.py --skip-merge \\
    --merged-hf exports/qwen35-2b-blue-merged-hf \\
    --llama-cpp "$_LLC" \\
    --gguf-out exports/qwen35-2b-blue-f16.gguf \\
    --ollama-model agentshield-blue-qwen35-2b
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _merge_peft(
    *,
    base_model: str,
    adapter_dir: Path,
    merged_out: Path,
    device: str,
) -> None:
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    merged_out.mkdir(parents=True, exist_ok=True)
    print(f"[merge] base={base_model}\n[merge] adapter={adapter_dir}\n[merge] out={merged_out}", flush=True)

    dtype = torch.float16 if device in ("cuda", "mps") else torch.float32
    if device == "cuda":
        base = AutoModelForCausalLM.from_pretrained(
            base_model,
            torch_dtype=dtype,
            device_map="auto",
            low_cpu_mem_usage=True,
            trust_remote_code=True,
        )
    else:
        # CPU/MPS: merge 안정성 위해 CPU에 올린 뒤 merge (MPS 직접은 일부 환경에서 merge 이슈)
        base = AutoModelForCausalLM.from_pretrained(
            base_model,
            torch_dtype=dtype if dtype == torch.float32 else torch.float16,
            device_map="cpu",
            low_cpu_mem_usage=True,
            trust_remote_code=True,
        )

    tok = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    if tok.pad_token_id is None and tok.eos_token:
        tok.pad_token = tok.eos_token

    model = PeftModel.from_pretrained(base, str(adapter_dir))
    merged = model.merge_and_unload()
    merged.eval()
    merged.save_pretrained(str(merged_out), safe_serialization=True)
    tok.save_pretrained(str(merged_out))
    print("[merge] 완료 (HF merged)", flush=True)


def _find_convert_script(llama_cpp: Path) -> Path | None:
    for name in ("convert_hf_to_gguf.py", "convert-hf-to-gguf.py"):
        p = llama_cpp / name
        if p.is_file():
            return p
    return None


def _run_gguf_convert(
    *,
    llama_cpp: Path,
    merged_hf: Path,
    gguf_out: Path,
    outtype: str,
    python_exe: str,
) -> None:
    script = _find_convert_script(llama_cpp)
    if script is None:
        raise FileNotFoundError(
            f"llama.cpp 에서 convert_hf_to_gguf.py 를 찾지 못함: {llama_cpp} "
            "(ggml-org/llama.cpp 최신 클론 권장)"
        )
    gguf_out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        python_exe,
        str(script),
        str(merged_hf),
        "--outfile",
        str(gguf_out),
        "--outtype",
        outtype,
    ]
    print(f"[gguf] 실행: {' '.join(cmd)}", flush=True)
    proc = subprocess.run(
        cmd,
        cwd=str(llama_cpp),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        err = (proc.stderr or "") + (proc.stdout or "")
        print(err[-4000:] if len(err) > 4000 else err, flush=True)
        if "BPE pre-tokenizer" in err or "chkhsh" in err or "NotImplementedError" in err:
            print(
                "\n[gguf 실패 안내] 토크나이저 pre-hash 가 llama.cpp 에 등록되지 않았을 때 흔합니다.\n"
                "  1) llama.cpp 최신으로 갱신:  cd <llama.cpp> && git pull origin master\n"
                "  2) 필요 시: python convert_hf_to_gguf_update.py  (저장소 문서 참고, HF_TOKEN)\n"
                "  3) 동일 명령으로 merge 스크립트 재실행 (--skip-merge)\n",
                flush=True,
            )
        raise subprocess.CalledProcessError(proc.returncode, cmd, proc.stdout, proc.stderr)
    print(f"[gguf] 완료: {gguf_out}", flush=True)


def _write_modelfile(gguf_out: Path, modelfile: Path) -> None:
    # Modelfile은 GGUF와 같은 디렉터리에 두고 상대 경로로 FROM (ollama create cwd 기준)
    name = gguf_out.name
    modelfile.write_text(f"FROM ./{name}\n", encoding="utf-8")


def _run_ollama_create(*, ollama_model: str, modelfile_dir: Path) -> None:
    if not shutil.which("ollama"):
        print("[ollama] ollama CLI 없음 — Modelfile만 생성했습니다.", flush=True)
        return
    cmd = ["ollama", "create", ollama_model, "-f", "Modelfile"]
    print(f"[ollama] {' '.join(cmd)} (cwd={modelfile_dir})", flush=True)
    subprocess.run(cmd, check=True, cwd=str(modelfile_dir))
    print(f"[ollama] 등록됨: {ollama_model}", flush=True)


def main() -> int:
    root = _project_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    ap = argparse.ArgumentParser(description="Merge PEFT → HF → GGUF (llama.cpp) → Ollama")
    ap.add_argument("--base-model", default="Qwen/Qwen3.5-4B", help="HF 베이스 모델 id")
    ap.add_argument(
        "--adapter",
        default="adapters/lora-blue-qwen",
        help="PEFT 어댑터 디렉터리 (adapter_config.json 위치)",
    )
    ap.add_argument(
        "--merged-hf",
        default="exports/qwen35-blue-merged-hf",
        help="merge된 HF 저장 경로",
    )
    ap.add_argument("--skip-merge", action="store_true", help="이미 merge된 HF가 있으면 GGUF 단계만")
    ap.add_argument(
        "--device",
        choices=["auto", "cpu", "cuda", "mps"],
        default="auto",
        help="merge 로드 디바이스 (auto: cuda>mps>cpu)",
    )
    ap.add_argument(
        "--llama-cpp",
        default=None,
        help="llama.cpp 저장소 루트 (convert_hf_to_gguf.py 포함). 없으면 GGUF 단계 생략",
    )
    ap.add_argument(
        "--gguf-out",
        default="exports/qwen35-blue-f16.gguf",
        help="출력 GGUF 파일 경로",
    )
    ap.add_argument(
        "--outtype",
        default="f16",
        help="convert_hf_to_gguf.py --outtype (f16, bf16, f32, auto 등; Qwen3는 bf16 권장 문서도 있음)",
    )
    ap.add_argument(
        "--ollama-model",
        default=None,
        help="지정 시 Modelfile 작성 후 ollama create <이름>",
    )
    ap.add_argument(
        "--python",
        default=sys.executable,
        help="convert_hf_to_gguf.py 실행에 쓸 Python (llama.cpp 권장: 같은 venv 또는 시스템 python3)",
    )
    args = ap.parse_args()

    # convert subprocess cwd=llama.cpp 이므로 상대 경로 python 은 프로젝트 루트 기준으로 절대화
    _py = Path(args.python).expanduser()
    if not _py.is_absolute():
        _py = (root / _py).resolve()
    args.python = str(_py)

    adapter_dir = (root / args.adapter).resolve()
    merged_hf = (root / args.merged_hf).resolve()
    gguf_out = (root / args.gguf_out).resolve()

    if not adapter_dir.is_dir():
        print(f"[error] adapter 디렉터리 없음: {adapter_dir}", flush=True)
        return 1
    if not (adapter_dir / "adapter_config.json").is_file():
        print(f"[error] adapter_config.json 없음: {adapter_dir}", flush=True)
        return 1

    import torch

    if args.device == "auto":
        if torch.cuda.is_available():
            dev = "cuda"
        elif getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            dev = "mps"
        else:
            dev = "cpu"
    else:
        dev = args.device

    if not args.skip_merge:
        _merge_peft(
            base_model=args.base_model,
            adapter_dir=adapter_dir,
            merged_out=merged_hf,
            device=dev,
        )
    else:
        if not merged_hf.is_dir() or not (merged_hf / "config.json").is_file():
            print(f"[error] --skip-merge 인데 merged HF 없음: {merged_hf}", flush=True)
            return 1
        print(f"[merge] 생략 (--skip-merge), 사용: {merged_hf}", flush=True)

    if args.llama_cpp:
        llama_cpp = Path(os.path.expanduser(args.llama_cpp)).resolve()
        if not llama_cpp.is_dir():
            print(f"[error] --llama-cpp 경로 없음: {llama_cpp}", flush=True)
            return 1
        _run_gguf_convert(
            llama_cpp=llama_cpp,
            merged_hf=merged_hf,
            gguf_out=gguf_out,
            outtype=args.outtype,
            python_exe=args.python,
        )
    else:
        print(
            "\n[다음 단계] llama.cpp 가 있으면 --llama-cpp 로 넘기거나 수동 예:\n"
            "  (이 Mac 고정 경로) "
            "/Users/parkjoyeong/Desktop/Park Joyeong/Class/Projects/3. final/llama.cpp\n"
            f"  {args.python} <llama.cpp>/convert_hf_to_gguf.py \\\n"
            f"    {merged_hf} --outfile {gguf_out} --outtype {args.outtype}\n",
            flush=True,
        )

    if args.ollama_model:
        if not gguf_out.is_file():
            print(
                f"[error] GGUF 파일이 없어 Ollama 등록 불가: {gguf_out}\n"
                "  --llama-cpp 로 변환을 먼저 완료하세요.",
                flush=True,
            )
            return 1
        mf_dir = gguf_out.parent
        mf_path = mf_dir / "Modelfile"
        _write_modelfile(gguf_out, mf_path)
        print(f"[ollama] Modelfile 작성: {mf_path}", flush=True)
        _run_ollama_create(ollama_model=args.ollama_model, modelfile_dir=mf_dir)

    print(
        "\n=== .env 예 (블루를 Ollama GGUF로) ===\n"
        "USE_LOCAL_PEFT=false\n"
        f"OLLAMA_BLUE_TARGET_MODEL={args.ollama_model or '<ollama에 등록한 이름>'}\n"
        "OLLAMA_BASE_URL=http://localhost:11434\n",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
