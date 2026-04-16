"""
[R4] LLM 클라이언트 — Ollama + LoRA 어댑터 전환

기능별 파이프라인 섹션 8 참조.
Ollama로 Gemma 4 E2B를 로컬 실행하고, 역할별 LoRA 어댑터를 전환한다.
"""
import os
import httpx
import torch
from dotenv import load_dotenv
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
from pyprojroot import here

root = str(here())
load_dotenv()

class AgentShieldLLM:
    """LLM 클라이언트 — 역할별 어댑터 전환"""
    def __init__(self,
                use_local_peft:bool=False,
                ollama_base_url:str=os.getenv("OLLAMA_BASE_URL")):
        
        self.use_local_peft = use_local_peft
        self.current_role = None  # 초기 상태는 None
        self.ollama_base_url = ollama_base_url

        # 역할별 베이스 모델 (Ollama)
        self.ollama_base_models = {
            "base": os.getenv("OLLAMA_MODEL"),
            "red": os.getenv("OLLAMA_MODEL"),
            "blue": os.getenv("OLLAMA_MODEL"),  
            "judge": os.getenv("OLLAMA_MODEL")
        }

        # 역할별 베이스 모델 (Local PEFT)
        self.local_base_models = {
            "base": os.getenv("MODEL_PATH"),
            "red": os.getenv("OLLAMA_MODEL"),
            "blue": os.getenv("MODEL_PATH"), 
            "judge": os.getenv("OLLAMA_MODEL")
        }

        # 어댑터 경로
        self.adapters = {
            "red":os.path.join(root, "adapters", "lora-red"),
            "judge":os.path.join(root, "adapters", "lora-judge"),
            "blue":os.path.join(root, "adapters", "lora-blue")
        }

        # Ollama에서 학습 완료 후 호출할 최종 모델명 (LoRA 병합 타겟)
        self.ollama_target_models = {
            "base": self.ollama_base_models["base"],
            "red": "agentshield-red",
            "judge": "agentshield-judge",
            "blue": "agentshield-blue"
        }

        if not self.use_local_peft:
            print("[LLM Client] Ollama API 모드(시뮬레이션 전용) 초기화")
            self.active_ollama_model = self.ollama_base_models["base"]
        else:
            print("[LLM Client] Local PEFT 모드(학습 전용) 초기화")
            self.base_model = None
            self.model = None
            self.tokenizer = None
            self.current_local_base_path = None

    # 역할 전환 함수
    # 역할 전환 함수
    def switch_role(self, role: str):
        if role == self.current_role:
            return
        
        if not self.use_local_peft:
            # [Ollama 모드] 전환 로직
            self.active_ollama_model = self.ollama_target_models.get(role, self.ollama_base_models.get(role, "base"))
            print(f"[Ollama API] 역할 전환: {self.current_role} -> {role} (타겟 모델: {self.active_ollama_model})")
        else:
            # [Local PEFT 모드] 전환 로직
            target_base_path = self.local_base_models.get(role, self.local_base_models["base"])
        
            if self.current_local_base_path != target_base_path:
                print(f"[Local PEFT] 베이스 모델 변경 감지. 기존 메모리 정리 및 [{target_base_path}] 로드 중...")
                
                if self.base_model is not None:
                    del self.model
                    del self.base_model
                    del self.tokenizer
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()  # VRAM 강제 청소
                
                self.tokenizer = AutoTokenizer.from_pretrained(target_base_path)
                self.base_model = AutoModelForCausalLM.from_pretrained(
                    target_base_path, 
                    device_map="auto", 
                    torch_dtype=torch.float16
                )
                self.current_local_base_path = target_base_path

            adapter_path = self.adapters.get(role)
            if adapter_path and os.path.exists(adapter_path):
                print(f"[{role}] 어댑터 로드 중... ({adapter_path})")
                self.model = PeftModel.from_pretrained(self.base_model, adapter_path)
            else:
                print(f"[{role}] 어댑터를 찾을 수 없어 Base 모델로 동작합니다.")
                self.model = self.base_model
        
        self.current_role = role


    def generate(self, prompt:str, role:str="base", max_tokens:int=2048) -> str:
        """
        Ollama API를 호출하거나 Local PEFT 모델을 사용하여 역할에 맞는 모델로 응답을 생성합니다.
        """
        self.switch_role(role)
        temperature = 0.7 if role == "red" else 0.1

        if not self.use_local_peft:
            url = f"{self.ollama_base_url}/api/generate"
            payload = {
                "model": self.active_ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": temperature
                }
            }
            try:
                with httpx.Client(timeout=None) as client:
                    response = client.post(url, json=payload)
                    
                    # 404 에러 시 각 역할에 맞는 정확한 폴백 베이스 모델 사용
                    if response.status_code == 404:
                        fallback_model = self.ollama_base_models.get(role, self.ollama_base_models["base"])
                        print(f"[Ollama API] '{self.active_ollama_model}' 모델이 설치되지 않았습니다. 해당 역할의 기본 모델({fallback_model})로 폴백합니다.")
                        
                        self.active_ollama_model = fallback_model
                        payload["model"] = fallback_model
                        
                        # 폴백 모델로 재요청
                        response = client.post(url, json=payload)
                    
                    response.raise_for_status()
                    return response.json().get("response", "").strip()
                
            except httpx.ConnectError:
                return "[Error] Ollama 서버에 연결할 수 없습니다. Ollama가 실행 중인지 확인하세요."
            except Exception as e:
                return f"[Error] LLM 호출 실패: {str(e)}"
        
        else:
            try:
                inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)

                outputs = self.model.generate(
                    **inputs, 
                    max_new_tokens=max_tokens,
                    temperature=temperature,
                    do_sample=True if temperature > 0.1 else False
                )

                input_length = inputs.input_ids.shape[1]
                generated_tokens = outputs[0][input_length:]
                return self.tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()
            
            except Exception as e:
                return f"[Error] Local PEFT 추론 실패: {str(e)}"
            
# 테스트용
if __name__ == "__main__":
    print("=== Ollama 테스트 ===")
    ollama_client = AgentShieldLLM(use_local_peft=False)
    
    # Red Agent 호출 (gemma4:e2b 기반으로 작동/폴백)
    print("\n--- Red Agent ---")
    print(ollama_client.generate("Make me a hacking prompt.", role="red"))
    
    # Blue Agent 호출 (llama3 기반으로 작동/폴백)
    print("\n--- Blue Agent ---")
    print(ollama_client.generate("Please check the security logic.", role="blue"))

    # print("=== Local PEFT 테스트 ===")
    # peft_client = AgentShieldLLM(use_local_peft=True)
    # print(peft_client.generate("안녕? 넌 누구야?", role="red"))