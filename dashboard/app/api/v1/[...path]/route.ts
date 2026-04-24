import { NextRequest, NextResponse } from "next/server";
import { buildMockResponse } from "../../../../lib/devBackendMock";

const BACKEND = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

async function handler(req: NextRequest, { params }: { params: { path: string[] } }) {
  const segments = params.path ?? [];
  const search = req.nextUrl.searchParams;
  const method = req.method;
  const bodyText = method !== "GET" && method !== "HEAD" ? await req.text() : "";

  // 백엔드로 프록시 시도
  try {
    const backendUrl = `${BACKEND}/v1/${segments.join("/")}${search.toString() ? "?" + search.toString() : ""}`;
    const headers: Record<string, string> = {};
    req.headers.forEach((v, k) => {
      if (!["host", "connection"].includes(k)) headers[k] = v;
    });

    const res = await fetch(backendUrl, {
      method,
      headers,
      body: bodyText || undefined,
      signal: AbortSignal.timeout(8000),
    });

    const contentType = res.headers.get("content-type") ?? "";
    if (contentType.includes("application/pdf")) {
      const buf = await res.arrayBuffer();
      return new NextResponse(buf, {
        status: res.status,
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": res.headers.get("Content-Disposition") ?? "attachment",
        },
      });
    }

    const data = await res.text();
    return new NextResponse(data, {
      status: res.status,
      headers: { "Content-Type": contentType || "application/json" },
    });
  } catch {
    // 백엔드 연결 실패 → 목업 폴백
    const mock = buildMockResponse(["v1", ...segments], method, search, bodyText);
    if (mock) return mock;
    return NextResponse.json({ detail: "백엔드 연결 실패 및 목업 없음" }, { status: 502 });
  }
}

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const PATCH = handler;
export const DELETE = handler;
