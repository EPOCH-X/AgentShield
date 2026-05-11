import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import path from "node:path";
import { NextRequest, NextResponse } from "next/server";

const root = process.env.AGENTSHIELD_ROOT || path.resolve(process.cwd(), "..");
const python = process.env.PYTHON_BIN || "python3";

function e(key: string, fallback = "") {
  return String(process.env[key] || fallback);
}

function toRound(record: Record<string, unknown>) {
  const attack = String(record.attack_prompt || "");
  const response = String(record.target_response || "");
  return {
    round: record.round,
    category: record.category,
    subcategory: record.subcategory,
    attack_prompt: attack,
    target_response: response,
    judgment: record.judgment,
    confidence: record.confidence,
    success: Boolean(record.success),
    success_strength: record.success_strength,
    exploit_type: record.exploit_type,
    detail: record.judge_detail,
    attack_len: attack.length,
    response_len: response.length,
    generation_failed: record.judgment === "generation_failed",
  };
}

function runRedAdaptive(prompt: string): Promise<{ status: number; stdout: string; stderr: string }> {
  const redModel = e("RED_CAMPAIGN_MODEL") || e("OLLAMA_RED_MODEL");
  const targetUrl = e("TESTBED_CHAT_URL", `http://127.0.0.1:${e("TESTBED_PORT", "8010")}/chat`);
  const rounds = e("RED_CAMPAIGN_ROUNDS", "5");

  return new Promise((resolve) => {
    const child = spawn(
      python,
      [
        "scripts/run_demo_red_adaptive_rounds.py",
        "--target-url", targetUrl,
        "--red-model", redModel,
        "--rounds", rounds,
        "--seed", "57",
        "--category", "LLM02",
        "--subcategory", "config-extraction",
        "--initial-prompt-stdin",
      ],
      {
        cwd: root,
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...process.env,
          RED_CAMPAIGN_CONTINUE_AFTER_SUCCESS: e("DEMO_RED_CONTINUE_AFTER_SUCCESS", "false"),
          RED_CAMPAIGN_STOP_ON_VULNERABLE: "true",
        },
      }
    );

    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
    }, 600_000);

    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("close", (code) => {
      clearTimeout(timeout);
      resolve({ status: code ?? 1, stdout, stderr });
    });
    child.stdin.end(prompt);
  });
}

function streamRedAdaptive(prompt: string, targetResponse: string) {
  const encoder = new TextEncoder();
  const redModel = e("RED_CAMPAIGN_MODEL") || e("OLLAMA_RED_MODEL");
  const targetUrl = e("TESTBED_CHAT_URL", `http://127.0.0.1:${e("TESTBED_PORT", "8010")}/chat`);
  const rounds = e("RED_CAMPAIGN_ROUNDS", "5");
  const campaignId = `demo-red-${Date.now().toString(36)}`;
  const seedPath = path.join(os.tmpdir(), `${campaignId}.json`);
  const livePath = path.join(root, "data", "red_campaigns", "live", `${campaignId}.jsonl`);
  const rawPath = path.join(root, "data", "red_campaigns", "raw", `${campaignId}_raw.json`);
  fs.writeFileSync(seedPath, JSON.stringify([
    {
      id: campaignId,
      seed_id: "demo-ui-seed",
      category: "LLM02",
      subcategory: "config-extraction",
      attack_prompt: prompt,
      target_response: targetResponse,
      detail: "Dashboard demo seed prompt",
    },
  ], null, 2), "utf8");

  const send = (controller: ReadableStreamDefaultController<Uint8Array>, event: Record<string, unknown>) => {
    controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
  };

  return new ReadableStream<Uint8Array>({
    start(controller) {
      send(controller, { type: "status", detail: "Red Agent 라운드 실행 시작", campaign_id: campaignId });
      const child = spawn(
        python,
        [
          "scripts/run_red_adaptive_campaign.py",
          "--target-url", targetUrl,
          "--input", seedPath,
          "--seeds", "1",
          "--rounds", rounds,
          "--seed", "57",
          "--category", "LLM02",
          "--campaign-id", campaignId,
          "--conversation-mode", "multi",
          "--verify-tool-execution",
          "--stop-on-vulnerable",
          ...(redModel ? ["--red-model", redModel] : []),
        ],
        {
          cwd: root,
          stdio: ["ignore", "pipe", "pipe"],
          env: {
            ...process.env,
            RED_CAMPAIGN_CONTINUE_AFTER_SUCCESS: "false",
            RED_CAMPAIGN_STOP_ON_VULNERABLE: "true",
          },
        },
      );

      let readOffset = 0;
      let stderr = "";
      let stdoutTail = "";
      const seenRounds = new Set<string>();

      const flushLive = () => {
        if (!fs.existsSync(livePath)) return;
        const text = fs.readFileSync(livePath, "utf8");
        const next = text.slice(readOffset);
        readOffset = text.length;
        for (const line of next.split(/\n/).filter(Boolean)) {
          try {
            const record = JSON.parse(line);
            const key = `${record.round}:${record.ts || ""}:${String(record.attack_prompt || "").length}`;
            if (seenRounds.has(key)) continue;
            seenRounds.add(key);
            send(controller, { type: "round", round: toRound(record) });
            if (record.judgment === "vulnerable") {
              send(controller, { type: "status", detail: `R${record.round} vulnerable 판정. 라운드 중지` });
            }
          } catch {
            // ignore partial line
          }
        }
      };

      const timer = setInterval(flushLive, 700);
      const timeout = setTimeout(() => child.kill("SIGTERM"), 600_000);

      child.stdout.on("data", (chunk) => {
        stdoutTail = `${stdoutTail}${chunk.toString()}`.slice(-4000);
        flushLive();
      });
      child.stderr.on("data", (chunk) => {
        stderr = `${stderr}${chunk.toString()}`.slice(-4000);
      });
      child.on("close", (code) => {
        clearInterval(timer);
        clearTimeout(timeout);
        flushLive();
        let bestRound: number | null = null;
        let success = false;
        if (fs.existsSync(rawPath)) {
          try {
            const raw = JSON.parse(fs.readFileSync(rawPath, "utf8"));
            const item = Array.isArray(raw.items) ? raw.items[0] : null;
            bestRound = item?.best_round ?? null;
            success = Boolean(item?.success);
          } catch {
            // ignore final summary parse error
          }
        }
        try {
          fs.unlinkSync(seedPath);
        } catch {
          // ignore
        }
        send(controller, {
          type: "done",
          ok: code === 0,
          status: code ?? 1,
          raw_path: fs.existsSync(rawPath) ? rawPath : null,
          best_round: bestRound,
          success,
          stderr_tail: stderr,
          stdout_tail: stdoutTail,
        });
        controller.close();
      });
    },
  });
}

export async function POST(req: NextRequest) {
  let body: { prompt?: string; target_response?: string; stream?: boolean };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ detail: "요청 본문이 올바르지 않습니다." }, { status: 400 });
  }

  const prompt = String(body.prompt || "").trim();
  if (!prompt) {
    return NextResponse.json({ detail: "프롬프트를 입력해 주세요." }, { status: 400 });
  }

  if (body.stream) {
    return new Response(streamRedAdaptive(prompt, String(body.target_response || "")), {
      headers: {
        "Content-Type": "application/x-ndjson; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
      },
    });
  }

  const result = await runRedAdaptive(prompt);
  const lastLine = result.stdout.trim().split(/\n/).filter(Boolean).at(-1) || "{}";

  try {
    const payload = JSON.parse(lastLine);
    return NextResponse.json(
      { ...payload, status: result.status, stderr_tail: payload.stderr_tail || result.stderr.slice(-4000) },
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
