import { spawn } from "node:child_process";
import path from "node:path";
import { NextResponse } from "next/server";

const root = process.env.AGENTSHIELD_ROOT || path.resolve(process.cwd(), "..");
const python = process.env.PYTHON_BIN || "python3";

function e(key: string, fallback = "") {
  return String(process.env[key] || fallback);
}

function testbedPort() {
  return e("TESTBED_PORT", "8010");
}
function testbedHostUrl() {
  return e("TESTBED_BASE_URL", `http://127.0.0.1:${testbedPort()}`);
}
function publicTestbedUrl() {
  return e("TESTBED_PUBLIC_URL", `http://localhost:${testbedPort()}`);
}
function toolGatewayUrl() {
  return e("TOOL_GATEWAY_URL", `http://localhost:${e("TOOL_GATEWAY_PORT", "8020")}`);
}
function toolGatewayServerUrl() {
  return e("TOOL_GATEWAY_INTERNAL_URL", e("TOOL_GATEWAY_URL", `http://127.0.0.1:${e("TOOL_GATEWAY_PORT", "8020")}`));
}
function maskUrlPassword(value: string) {
  return value.replace(/:\/\/([^:\s/@]+):([^@\s]+)@/, "://$1:***@");
}

async function readTargetHealth() {
  try {
    const res = await fetch(`${testbedHostUrl()}/health`, {
      signal: AbortSignal.timeout(3_000),
      cache: "no-store",
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

const RUNTIME_RISK: Record<string, string> = {
  INTERNAL_API_KEY: "critical",
  DB_ROOT_PASSWORD: "high",
  NODE_ENV: "medium",
  SERVICE_NAME: "medium",
  AUTH_TOKEN_EXPIRY: "low",
};

// weak 모드의 testbed가 실제 값을 반환하므로 dashboard에서 추가 마스킹하지 않는다.
// (testbed `tool_gateway`가 security_mode에 따라 이미 [REDACTED] 처리)

async function readRuntimeContext(mode: string) {
  try {
    const res = await fetch(`${toolGatewayServerUrl()}/runtime/context?mode=${encodeURIComponent(mode || "weak")}`, {
      signal: AbortSignal.timeout(3_000),
      cache: "no-store",
    });
    if (!res.ok) return null;
    const data = await res.json();
    const context = data?.context;
    if (!context) return null;
    return context as {
      runtime_secrets?: Array<{ key?: string; value?: string }>;
      registered_tools?: Array<{ tool_name?: string; auth_level?: string; description?: string }>;
    };
  } catch {
    return null;
  }
}

function readDbSnapshot(): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const child = spawn(python, ["scripts/read_testbed_snapshot.py"], {
      cwd: root,
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });

    let stdout = "";
    const timeout = setTimeout(() => child.kill("SIGTERM"), 4_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.on("close", () => {
      clearTimeout(timeout);
      try {
        resolve(JSON.parse(stdout.trim().split(/\n/).filter(Boolean).at(-1) || "{}"));
      } catch {
        resolve({ ok: false });
      }
    });
  });
}

export async function GET() {
  const health = await readTargetHealth();
  const securityMode = health?.security_mode || e("TESTBED_SECURITY_MODE", "weak");
  const runtime = await readRuntimeContext(securityMode);
  const dbSnapshot = await readDbSnapshot();
  const runtimeContext = runtime?.runtime_secrets?.length
    ? runtime.runtime_secrets.map((item) => {
        const key = String(item.key || "");
        const value = String(item.value ?? "");
        return { key, value, risk: RUNTIME_RISK[key] || "medium" };
      })
    : [];
  const tools = runtime?.registered_tools?.length
    ? runtime.registered_tools.map((tool) => ({
        name: String(tool.tool_name || ""),
        risk: String(tool.auth_level || "read"),
        description: String(tool.description || ""),
      }))
    : [];

  return NextResponse.json({
    target: {
      url: `${publicTestbedUrl()}/chat`,
      health_url: `${publicTestbedUrl()}/health`,
      tool_gateway_url: toolGatewayUrl(),
      model: health?.model || e("OLLAMA_MODEL"),
      security_mode: securityMode,
      environment: "Docker testbed",
      health_status: health?.status || "offline",
      allow_stub_tools: String(health?.allow_stub_tools ?? e("ALLOW_STUB_TOOLS", "false")),
      testbed_db_url: maskUrlPassword(e("TESTBED_DB_URL")),
    },
    runtime_context: runtimeContext,
    tools,
    db_snapshot: dbSnapshot,
  });
}
