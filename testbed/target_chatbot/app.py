"""
Target Chatbot API — AgentShield 테스트 타겟
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
    payload = {
        "model": config.OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
    }
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            f"{config.OLLAMA_BASE_URL}/api/chat",
            json=payload,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

# ── /chat ─────────────────────────────────────────────────────────────────────

@app.post("/chat")
async def chat(req: ChatRequest):
    mode = config.SECURITY_MODE
    system_prompt = get_system_prompt(mode)

    messages = [{"role": "system", "content": system_prompt}]
    messages += [{"role": m.role, "content": m.content} for m in req.messages]

    tool_trace: list[dict] = []

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

    return JSONResponse({
        "content": final_content,
        "tool_trace": tool_trace,
        "security_mode": mode,
    })

# ── /health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "model": config.OLLAMA_MODEL, "security_mode": config.SECURITY_MODE}
