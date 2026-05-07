import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { NextRequest, NextResponse } from "next/server";
import { envValue, loadAgentShieldEnv, projectRoot } from "../../../../lib/serverEnv";

function runRedAdaptive(prompt: string): Promise<{ status: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const root = projectRoot();
    const venvPython = path.join(root, "venv", "bin", "python");
    const python = process.env.PYTHON_BIN || (fs.existsSync(venvPython) ? venvPython : "python3");
    const redModel = envValue("RED_CAMPAIGN_MODEL") || envValue("OLLAMA_RED_MODEL");
    const targetUrl = envValue("TESTBED_CHAT_URL", `http://127.0.0.1:${envValue("TESTBED_PORT", "8010")}/chat`);
    const rounds = envValue("RED_CAMPAIGN_ROUNDS", "5");
    const child = spawn(
      python,
      [
        "scripts/run_demo_red_adaptive_rounds.py",
        "--target-url",
        targetUrl,
        "--red-model",
        redModel,
        "--rounds",
        rounds,
        "--seed",
        "57",
        "--category",
        "LLM02",
        "--subcategory",
        "config-extraction",
        "--initial-prompt-stdin",
      ],
      {
        cwd: root,
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...process.env,
          ...loadAgentShieldEnv(),
          RED_CAMPAIGN_CONTINUE_AFTER_SUCCESS: envValue("DEMO_RED_CONTINUE_AFTER_SUCCESS", "false"),
        },
      }
    );

    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
    }, 600_000);

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
    child.stdin.end(prompt);
  });
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

  const result = await runRedAdaptive(prompt);
  const lastLine = result.stdout.trim().split(/\n/).filter(Boolean).at(-1) || "{}";

  try {
    const payload = JSON.parse(lastLine);
    return NextResponse.json(
      {
        ...payload,
        status: result.status,
        stderr_tail: payload.stderr_tail || result.stderr.slice(-4000),
      },
      { status: payload.ok ? 200 : 502 }
    );
  } catch {
    return NextResponse.json(
      {
        ok: false,
        status: result.status,
        detail: "Red Agent 실행 결과를 파싱할 수 없습니다.",
        stdout_tail: result.stdout.slice(-4000),
        stderr_tail: result.stderr.slice(-4000),
      },
      { status: 502 }
    );
  }
}
