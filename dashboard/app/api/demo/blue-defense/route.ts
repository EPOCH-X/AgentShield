import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { NextRequest, NextResponse } from "next/server";
import { loadAgentShieldEnv, projectRoot } from "../../../../lib/serverEnv";

function runBlueDefense(payload: unknown): Promise<{ status: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const root = projectRoot();
    const venvPython = path.join(root, "venv", "bin", "python");
    const python = process.env.PYTHON_BIN || (fs.existsSync(venvPython) ? venvPython : "python3");
    const child = spawn(python, ["scripts/run_demo_blue_defense.py"], {
      cwd: root,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, ...loadAgentShieldEnv() },
    });

    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => child.kill("SIGTERM"), 300_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      resolve({ status: code ?? 1, stdout, stderr });
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

export async function POST(req: NextRequest) {
  let body: { category?: string; attack_prompt?: string; target_response?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ detail: "요청 본문이 올바르지 않습니다." }, { status: 400 });
  }

  const result = await runBlueDefense(body);
  const lastLine = result.stdout.trim().split(/\n/).filter(Boolean).at(-1) || "{}";
  try {
    const payload = JSON.parse(lastLine);
    return NextResponse.json(
      { ...payload, status: result.status, stderr_tail: result.stderr.slice(-4000) },
      { status: payload.ok ? 200 : 502 }
    );
  } catch {
    return NextResponse.json(
      {
        ok: false,
        status: result.status,
        detail: "Blue Agent 실행 결과를 파싱할 수 없습니다.",
        stdout_tail: result.stdout.slice(-4000),
        stderr_tail: result.stderr.slice(-4000),
      },
      { status: 502 }
    );
  }
}
