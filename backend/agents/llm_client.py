"""
[R4 담당 / 연동 정리: Copilot] LLM 클라이언트 — Ollama + LoRA 어댑터 전환

기능별 파이프라인 섹션 8 참조.
Ollama로 Gemma 4 E2B를 로컬 실행하고, 역할별 LoRA 어댑터를 전환한다.
로컬 PEFT 경로는 선택 기능이므로, 관련 패키지가 없어도 Ollama 경로 import는 깨지지 않아야 한다.
"""

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, Optional, Type

import httpx
import torch
from dotenv import load_dotenv
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer

root = str(Path(__file__).resolve().parents[2])
load_dotenv()


class AgentShieldLLM:
    """LLM 클라이언트 — 역할별 어댑터 전환"""

    def __init__(
        self,
        use_local_peft: bool = False,
        ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
    ):
        self.use_local_peft = use_local_peft
        self.current_role = None
        self.ollama_base_url = ollama_base_url

        self.ollama_base_models = {
            "base": os.getenv("OLLAMA_MODEL"),
            "red": os.getenv("OLLAMA_RED_MODEL", os.getenv("OLLAMA_MODEL")),
            "blue": os.getenv("OLLAMA_BLUE_MODEL", os.getenv("OLLAMA_MODEL")),
            "judge": os.getenv("OLLAMA_JUDGE_MODEL", os.getenv("OLLAMA_MODEL")),
        }

        self.local_base_models = {
            "base": os.getenv("MODEL_PATH") or os.getenv("OLLAMA_MODEL"),
            "red": os.getenv("MODEL_PATH") or os.getenv("OLLAMA_MODEL"),
            "blue": os.getenv("MODEL_PATH") or os.getenv("OLLAMA_MODEL"),
            "judge": os.getenv("MODEL_PATH") or os.getenv("OLLAMA_MODEL"),
        }

        self.role_configs: Dict[str, Dict[str, Any]] = {
            "base": {
                "local_model": self.local_base_models["base"],
                "ollama_model": self.ollama_base_models["base"],
                "temperature": 0.1,
                "top_p": 0.95,
                "top_k": 64,
                "num_ctx": 8192,
                "adapter_path": None,
            },
            "red": {
                "local_model": self.local_base_models["red"],
                "ollama_model": self.ollama_base_models["red"],
                "temperature": 1.0,
                "top_p": 0.95,
                "top_k": 64,
                "num_ctx": 8192,
                "adapter_path": os.path.join(root, "adapters", "lora-red"),
                "think": False,  # disable thinking — red agent needs direct prompt output
            },
            "blue": {
                "local_model": self.local_base_models["blue"],
                "ollama_model": self.ollama_base_models["blue"],
                "temperature": 0.1,
                "top_p": 0.95,
                "top_k": 64,
                "num_ctx": 8192,
                "adapter_path": os.path.join(root, "adapters", "lora-blue"),
            },
            "judge": {
                "local_model": self.local_base_models["judge"],
                "ollama_model": self.ollama_base_models["judge"],
                "temperature": 0.0,
                "top_p": 1,
                "top_k": 1,
                "num_ctx": 16384,
                "adapter_path": os.path.join(root, "adapters", "lora-judge"),
            },
        }

        self.ollama_target_models = {
            "red": os.getenv("OLLAMA_RED_TARGET_MODEL", "agentshield-red"),
            "judge": os.getenv("OLLAMA_JUDGE_TARGET_MODEL", "agentshield-judge"),
            "blue": os.getenv("OLLAMA_BLUE_TARGET_MODEL", "agentshield-blue"),
            "base": os.getenv("OLLAMA_BASE_TARGET_MODEL", self.role_configs["base"]["ollama_model"]),
        }

        if not self.use_local_peft:
            print("[LLM Client] Ollama API 모드(시뮬레이션 전용) 초기화")
            self.active_ollama_model = self.ollama_target_models["base"]
        else:
            print("[LLM Client] Local PEFT 모드(학습 전용) 초기화")
            self.base_model = None
            self.model = None
            self.tokenizer = None
            self.current_local_base_path = None

    @staticmethod
    def _load_peft_model(base_model: Any, adapter_path: str) -> Any:
        try:
            from peft import PeftModel
        except ImportError as exc:
            raise RuntimeError(
                "Local PEFT 모드를 사용하려면 peft 패키지가 필요합니다. "
                "현재는 Ollama 경로만 사용 가능합니다."
            ) from exc

        return PeftModel.from_pretrained(base_model, adapter_path)

    def switch_role(self, role: str):
        if role == self.current_role:
            return

        role_config = self.role_configs.get(role, self.role_configs["base"])

        if not self.use_local_peft:
            self.active_ollama_model = self.ollama_target_models.get(role, role_config["ollama_model"])
            print(f"[Ollama API] 역할 전환: {self.current_role} -> {role} (타겟 모델: {self.active_ollama_model})")
        else:
            target_base_path = role_config["local_model"]

            if self.current_local_base_path != target_base_path:
                print(f"[Local PEFT] 베이스 모델 변경 감지. 기존 메모리 정리 및 [{target_base_path}] 로드 중...")

                if self.base_model is not None:
                    del self.model
                    del self.base_model
                    del self.tokenizer
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()

                self.tokenizer = AutoTokenizer.from_pretrained(target_base_path)
                self.base_model = AutoModelForCausalLM.from_pretrained(
                    target_base_path,
                    device_map="auto",
                    torch_dtype=torch.float16,
                )
                self.current_local_base_path = target_base_path

            adapter_path = role_config.get("adapter_path")
            if adapter_path and os.path.exists(adapter_path):
                print(f"[{role}] 어댑터 로드 중... ({adapter_path})")
                self.model = self._load_peft_model(self.base_model, adapter_path)
            else:
                print(f"[{role}] 어댑터를 찾을 수 없어 Base 모델로 동작합니다.")
                self.model = self.base_model

        self.current_role = role

    @staticmethod
    def parse_thinking_output(response: str) -> str:
        if "<channel|>" in response:
            return response.split("<channel|>")[-1].strip()
        if "</think>" in response:
            return response.split("</think>")[-1].strip()
        return response.strip()

    async def generate(
        self,
        prompt: str,
        role: str = "base",
        max_tokens: int = 2048,
        response_model: Optional[Type[BaseModel]] = None,
    ) -> Any:
        """역할에 맞는 모델로 텍스트 또는 구조화된 응답을 생성한다."""
        self.switch_role(role)
        role_config = self.role_configs.get(role, self.role_configs["base"])
        options = {
            "num_predict": max_tokens,
            "temperature": role_config["temperature"],
            "top_p": role_config.get("top_p", 0.95),
            "top_k": role_config.get("top_k", 64),
            "num_ctx": role_config["num_ctx"],
        }

        if not self.use_local_peft:
            url = f"{self.ollama_base_url}/api/generate"
            payload = {
                "model": self.active_ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": options,
            }
            # Pass think parameter for thinking-capable models (Ollama 0.6+)
            think_val = role_config.get("think")
            if think_val is not None:
                payload["think"] = think_val
            if response_model:
                payload["format"] = response_model.model_json_schema()

            try:
                async with httpx.AsyncClient(timeout=None) as client:
                    response = await client.post(url, json=payload)
                    if response.status_code == 404:
                        fallback_model = role_config["ollama_model"]
                        print(f"[Ollama API] '{self.active_ollama_model}' 모델이 설치되지 않았습니다. 해당 역할의 기본 모델({fallback_model})로 폴백합니다.")
                        self.active_ollama_model = fallback_model
                        payload["model"] = fallback_model
                        response = await client.post(url, json=payload)

                    response.raise_for_status()
                    resp_json = response.json()
                    raw_text = resp_json.get("response", "")
                    # Ollama 0.6+ separates thinking from response for thinking models.
                    # If response is empty but thinking is present, use thinking content
                    # so the generation is not silently dropped.
                    if not raw_text.strip() and resp_json.get("thinking"):
                        raw_text = resp_json["thinking"]
                    cleaned_text = self.parse_thinking_output(raw_text)
                    if response_model:
                        try:
                            return response_model.model_validate_json(cleaned_text)
                        except Exception as exc:
                            print(f"[{role}] Pydantic 에러: {exc}\n원본: {cleaned_text}")
                            return None
                    return cleaned_text
            except httpx.ConnectError:
                return "[Error] Ollama 서버에 연결할 수 없습니다. Ollama가 실행 중인지 확인하세요."
            except Exception as exc:
                return f"[Error] LLM 호출 실패: {str(exc)}"

        try:
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                temperature=role_config["temperature"],
                do_sample=role_config["temperature"] > 0.1,
                top_p=role_config.get("top_p", 0.95),
            )
            input_length = inputs.input_ids.shape[1]
            generated_tokens = outputs[0][input_length:]
            raw_text = self.tokenizer.decode(generated_tokens, skip_special_tokens=True)
            cleaned_text = self.parse_thinking_output(raw_text)
            if response_model:
                try:
                    return response_model.model_validate_json(cleaned_text)
                except Exception as exc:
                    print(f"[{role}] Pydantic 에러: {exc}\n원본: {cleaned_text}")
                    return None
            return cleaned_text
        except Exception as exc:
            return f"[Error] Local PEFT 추론 실패: {str(exc)}"


llm_client = AgentShieldLLM()


async def _main():
    print("=== Ollama 테스트 ===")
    ollama_client = AgentShieldLLM(use_local_peft=False)
    print("\n--- Red Agent ---")
    print(await ollama_client.generate("Make me a hacking prompt.", role="red"))
    print("\n--- Blue Agent ---")
    print(await ollama_client.generate("Please check the security logic.", role="blue"))


if __name__ == "__main__":
    asyncio.run(_main())