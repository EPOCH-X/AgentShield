"""[공통 testbed / 주관: R7, 사용: R1/R2/R5] Target Chatbot API.

AgentShield 테스트 타겟.
POST /chat  {"messages": [...]} -> {"content": "..."}
"""

import json
import re
import time
import httpx

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import config
from .prompts import get_system_prompt
from .tool_router import execute_tool

app = FastAPI(title="AgentShield Testbed Chatbot")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 스키마 ────────────────────────────────────────────────────────────────────

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[Message]

# ── tool call 파싱 ────────────────────────────────────────────────────────────

_TOOL_CALL_RE = re.compile(r"<tool_call>(.*?)</tool_call>", re.DOTALL)

def parse_tool_calls(text: str) -> list[dict]:
    calls = []
    for m in _TOOL_CALL_RE.finditer(text):
        try:
            calls.append(json.loads(m.group(1).strip()))
        except json.JSONDecodeError:
            pass
    return calls

def strip_tool_calls(text: str) -> str:
    return _TOOL_CALL_RE.sub("", text).strip()

# ── Ollama 호출 ───────────────────────────────────────────────────────────────

async def call_ollama(messages: list[dict]) -> str:
    """Ollama API 호출 및 응답 파싱 (오류 처리 강화)
    
    [수정 사항]
    - try/except 추가: ConnectionError, TimeoutError, HTTPError 처리
    - 응답 구조 검증: message.content 존재 여부 확인
    - 자세한 로깅: 오류 발생 시 전체 스택 추적
    """
    payload = {
        "model": config.OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
    }
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{config.OLLAMA_BASE_URL}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
            
            response_json = resp.json()
            
            # 응답 구조 검증
            if not isinstance(response_json, dict):
                raise ValueError(f"Invalid response type: {type(response_json)}")
            
            message = response_json.get("message")
            if not isinstance(message, dict):
                raise ValueError(f"Missing or invalid 'message' field: {response_json}")
            
            content = message.get("content")
            if content is None:
                raise ValueError(f"Missing 'content' in message: {message}")
            
            return str(content).strip()
    
    except httpx.ConnectError as e:
        raise RuntimeError(f"Failed to connect to Ollama at {config.OLLAMA_BASE_URL}: {e}")
    except httpx.TimeoutException as e:
        raise RuntimeError(f"Ollama request timeout (120s): {e}")
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Ollama API error {e.response.status_code}: {e.response.text()}")
    except ValueError as e:
        raise RuntimeError(f"Invalid Ollama response format: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected Ollama error: {e}")

# ── /chat ─────────────────────────────────────────────────────────────────────

@app.post("/chat")
async def chat(req: ChatRequest):
    """Chat 엔드포인트: Ollama 기반 응답 생성 (오류 처리 강화)
    
    [수정 사항]
    - call_ollama 호출을 try/except로 감싸기
    - Ollama 서비스 불가능 시 503 Service Unavailable 반환
    - 자세한 오류 로깅으로 디버깅 지원
    """
    mode = config.SECURITY_MODE
    system_prompt = get_system_prompt(mode)

    messages = [{"role": "system", "content": system_prompt}]
    messages += [{"role": m.role, "content": m.content} for m in req.messages]

    tool_trace: list[dict] = []
    final_content = "[ERROR] Chat endpoint failed"

    try:
        # 최대 3회 tool call 루프
        for _ in range(3):
            raw = await call_ollama(messages)
            tool_calls = parse_tool_calls(raw)

            if not tool_calls:
                final_content = raw.strip()
                break

            # tool call 실행
            messages.append({"role": "assistant", "content": raw})
            for call in tool_calls:
                name = call.get("name", "")
                arguments = call.get("arguments", {})
                result = await execute_tool(name, arguments)

                tool_trace.append({
                    "tool": name,
                    "arguments": arguments,
                    "result": result,
                })

                messages.append({
                    "role": "user",
                    "content": f"[Tool result for {name}]: {json.dumps(result, ensure_ascii=False)}",
                })
        else:
            final_content = strip_tool_calls(raw)

    except RuntimeError as e:
        # call_ollama에서 발생한 오류 (Ollama 연결 실패, 응답 파싱 실패 등)
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Ollama error in /chat endpoint: {e}", exc_info=True)
        
        # 503 Service Unavailable 반환
        return JSONResponse(
            status_code=503,
            content={
                "content": "[Service Unavailable] Ollama service is not responding",
                "error": str(e),
                "tool_trace": [],
                "security_mode": mode,
            }
        )
    
    except Exception as e:
        # 예상 밖의 오류 (tool_router 오류, JSON 직렬화 오류 등)
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Unexpected error in /chat endpoint: {e}", exc_info=True)
        
        return JSONResponse(
            status_code=500,
            content={
                "content": "[Internal Error] Failed to process request",
                "error": str(e),
                "tool_trace": tool_trace,
                "security_mode": mode,
            }
        )

    return JSONResponse({
        "content": final_content,
        "tool_trace": tool_trace,
        "security_mode": mode,
    })

# ── Startup Health Check ────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_check():
    """애플리케이션 시작 시 Ollama 연결 확인
    
    [수정 사항]
    - 시작 시 Ollama 서비스 가용성 확인
    - 연결 불가 시 경고 로그 기록 (실패로 처리 안 함)
    - 향후 /chat 요청이 실패할 가능성 사전 감지
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{config.OLLAMA_BASE_URL}/api/tags")
            resp.raise_for_status()
            
            # Ollama가 응답했고 유효한 모델 목록을 반환했는지 확인
            data = resp.json()
            if "models" in data:
                logger.info(f"✓ Ollama connection OK: {config.OLLAMA_BASE_URL}")
                logger.info(f"  Available models: {len(data['models'])} loaded")
            else:
                logger.warning(f"⚠ Ollama responding but unexpected response format: {data}")
    
    except httpx.ConnectError:
        logger.error(f"✗ CRITICAL: Cannot connect to Ollama at {config.OLLAMA_BASE_URL}")
        logger.error("  Chatbot will fail on /chat requests until Ollama is available")
        logger.error(f"  Expected: {config.OLLAMA_BASE_URL}/api/tags")
    except httpx.TimeoutException:
        logger.error(f"✗ TIMEOUT: Ollama at {config.OLLAMA_BASE_URL} is not responding within 10s")
        logger.error("  Chatbot may experience timeouts on /chat requests")
    except Exception as e:
        logger.error(f"✗ Unexpected error checking Ollama: {e}")

# ── /health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model": config.OLLAMA_MODEL,
        "security_mode": config.SECURITY_MODE,
        "tool_gateway_url": config.TOOL_GATEWAY_URL,
        "allow_stub_tools": config.ALLOW_STUB_TOOLS,
    }
