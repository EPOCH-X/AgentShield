import { NextRequest, NextResponse } from "next/server";

const DEFAULT_TESTBED_CHAT_URL = "http://127.0.0.1:8010/chat";
const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";

function testbedChatUrl(): string {
  return process.env.TESTBED_CHAT_URL || DEFAULT_TESTBED_CHAT_URL;
}

function backendOrigin(): string {
  const raw = process.env.AGENTSHIELD_API_URL || process.env.BACKEND_URL || DEFAULT_BACKEND_URL;
  return raw.replace(/\/$/, "");
}

export async function POST(req: NextRequest) {
  let body: { prompt?: string };

  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ detail: "요청 본문이 올바르지 않습니다." }, { status: 400 });
  }

  const prompt = String(body.prompt || "").trim();
  if (!prompt) {
    return NextResponse.json({ detail: "프롬프트를 입력해 주세요." }, { status: 400 });
  }

  try {
    const upstream = await fetch(testbedChatUrl(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        messages: [{ role: "user", content: prompt }],
      }),
      signal: AbortSignal.timeout(60_000),
    });

    const text = await upstream.text();
    const contentType = upstream.headers.get("content-type") || "application/json";
    if (!upstream.ok || !contentType.includes("application/json")) {
      return new NextResponse(text, {
        status: upstream.status,
        headers: { "Content-Type": contentType },
      });
    }

    const data = JSON.parse(text);
    const original = String(data.content || data.response || "").trim();
    if (!original) {
      return NextResponse.json(data, { status: upstream.status });
    }

    try {
      const translateResp = await fetch(`${backendOrigin()}/api/v1/translate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: original,
          source_language: "auto",
          target_language: "ko",
        }),
        signal: AbortSignal.timeout(20_000),
      });
      const translated = await translateResp.json();
      if (!translateResp.ok) {
        throw new Error(translated.detail || "translation failed");
      }

      data.original_content = original;
      data.content = translated.translated_text;
      data.response = translated.translated_text;
      data.translated = true;
      data.translation_error = null;
    } catch (error) {
      data.original_content = original;
      data.translated = false;
      data.translation_error = error instanceof Error ? error.message : String(error);
    }

    return NextResponse.json(data, { status: upstream.status });
  } catch (error) {
    return NextResponse.json(
      {
        detail: "테스트베드 챗봇에 연결할 수 없습니다.",
        target: testbedChatUrl(),
        error: error instanceof Error ? error.message : String(error),
      },
      { status: 502 }
    );
  }
}
