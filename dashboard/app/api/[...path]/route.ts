import { NextRequest, NextResponse } from "next/server";

const DEFAULT_BACKEND = "http://127.0.0.1:8000";

function backendOrigin(): string {
  const raw = process.env.AGENTSHIELD_API_URL || DEFAULT_BACKEND;
  return raw.replace(/\/$/, "");
}

function joinApiPath(segments: string[]): string {
  return segments.join("/");
}

function copySafeResponseHeaders(from: Response, to: NextResponse): void {
  from.headers.forEach((value, key) => {
    const k = key.toLowerCase();
    if (k === "transfer-encoding") return;
    to.headers.set(key, value);
  });
}

async function forwardToBackend(
  req: NextRequest,
  segments: string[],
  method: string
): Promise<NextResponse> {
  const tail = joinApiPath(segments);
  const target = `${backendOrigin()}/api/${tail}${req.nextUrl.search}`;

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    const k = key.toLowerCase();
    if (k === "host") return;
    headers.set(key, value);
  });

  let bodyBuf: ArrayBuffer | undefined;
  if (method !== "GET" && method !== "HEAD") {
    bodyBuf = await req.arrayBuffer();
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);

  try {
    const upstream = await fetch(target, {
      method,
      headers,
      body: bodyBuf && bodyBuf.byteLength > 0 ? bodyBuf : undefined,
      signal: controller.signal,
      redirect: "manual",
    });
    clearTimeout(timeout);
    const buf = await upstream.arrayBuffer();
    const res = new NextResponse(buf, { status: upstream.status });
    copySafeResponseHeaders(upstream, res);
    return res;
  } catch {
    clearTimeout(timeout);
    return NextResponse.json(
      {
        detail: "백엔드에 연결할 수 없습니다.",
        backend: backendOrigin(),
      },
      { status: 503 }
    );
  }
}

type Ctx = { params: { path: string[] } };

export async function GET(req: NextRequest, ctx: Ctx) {
  const segments = ctx.params.path ?? [];
  return forwardToBackend(req, segments, "GET");
}

export async function POST(req: NextRequest, ctx: Ctx) {
  const segments = ctx.params.path ?? [];
  return forwardToBackend(req, segments, "POST");
}

export async function PUT(req: NextRequest, ctx: Ctx) {
  const segments = ctx.params.path ?? [];
  return forwardToBackend(req, segments, "PUT");
}

export async function PATCH(req: NextRequest, ctx: Ctx) {
  const segments = ctx.params.path ?? [];
  return forwardToBackend(req, segments, "PATCH");
}

export async function DELETE(req: NextRequest, ctx: Ctx) {
  const segments = ctx.params.path ?? [];
  return forwardToBackend(req, segments, "DELETE");
}
