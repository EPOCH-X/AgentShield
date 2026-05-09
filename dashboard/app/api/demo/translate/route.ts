import { NextRequest, NextResponse } from "next/server";

const OLLAMA_BASE_URL = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
const TRANSLATE_MODEL = process.env.OLLAMA_GUARD_MODEL || "qwen3.5:4b";

export async function POST(req: NextRequest) {
  let body: { text?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, translated: "" }, { status: 400 });
  }

  const text = String(body.text || "").trim();
  if (!text) return NextResponse.json({ ok: true, translated: "" });

  try {
    const res = await fetch(`${OLLAMA_BASE_URL}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: TRANSLATE_MODEL,
        messages: [
          {
            role: "system",
            content: "You are a professional Korean translator. Translate the given English text to natural Korean. Output only the Korean translation, no explanations or extra text.",
          },
          { role: "user", content: text },
        ],
        stream: false,
        options: { temperature: 0.1, num_predict: 1024 },
      }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!res.ok) {
      return NextResponse.json({ ok: false, translated: text });
    }

    const data = await res.json() as { message?: { content?: string } };
    const translated = data?.message?.content?.trim() || text;
    return NextResponse.json({ ok: true, translated });
  } catch {
    return NextResponse.json({ ok: false, translated: text });
  }
}
