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

function normalizeCategory(value: unknown) {
  const category = String(value || "").trim().toUpperCase();
  return ["LLM01", "LLM02", "LLM06", "LLM07"].includes(category) ? category : "LLM02";
}

function defaultSubcategory(category: string) {
  if (category === "LLM01") return "role_hijack";
  if (category === "LLM06") return "tool_abuse";
  if (category === "LLM07") return "system_leak";
  return "config-extraction";
}

function targetChatUrl() {
  return e("TESTBED_CHAT_URL", `http://127.0.0.1:${e("TESTBED_PORT", "8010")}/chat`);
}

function toRound(record: Record<string, unknown>) {
  const attack = String(record.attack_prompt || "");
  const response = String(record.target_response || "");
  const attempts = Array.isArray(record.generation_attempts) ? record.generation_attempts.length : undefined;
  const rawJudge = record.judge && typeof record.judge === "object" ? record.judge as Record<string, unknown> : {};
  const judge = {
    category: rawJudge.category ?? record.category,
    judgment: rawJudge.judgment ?? record.judgment,
    confidence: rawJudge.confidence ?? record.confidence ?? record.judgment_confidence,
    score: rawJudge.score ?? rawJudge.confidence ?? record.confidence ?? record.judgment_confidence,
    severity: rawJudge.severity ?? record.severity,
    detail: rawJudge.detail ?? record.detail ?? record.judge_detail,
    failure_mode: rawJudge.failure_mode ?? record.failure_mode ?? record.root_cause ?? record.exploit_type,
    mitre_technique_id: rawJudge.mitre_technique_id ?? record.mitre_technique_id,
    p_vulnerable: rawJudge.p_vulnerable ?? record.p_vulnerable,
    p_safe: rawJudge.p_safe ?? record.p_safe,
    probability_judgment: rawJudge.probability_judgment ?? record.probability_judgment,
    consensus_judgment: rawJudge.consensus_judgment ?? record.consensus_judgment,
    judgment_alignment: rawJudge.judgment_alignment ?? record.judgment_alignment,
    reason_sources: rawJudge.reason_sources,
    debug_nodes: rawJudge.debug_nodes,
  };
  return {
    round: record.round,
    category: record.category,
    subcategory: record.subcategory,
    attack_prompt: attack,
    target_response: response,
    judge,
    judgment: judge.judgment,
    confidence: judge.confidence,
    success: Boolean(record.success),
    success_strength: record.success_strength,
    exploit_type: record.exploit_type,
    detail: judge.detail,
    p_vulnerable: judge.p_vulnerable,
    p_safe: judge.p_safe,
    probability_judgment: judge.probability_judgment,
    consensus_judgment: judge.consensus_judgment,
    judgment_alignment: judge.judgment_alignment,
    reason_sources: judge.reason_sources,
    mitre_technique_id: judge.mitre_technique_id,
    failure_mode: judge.failure_mode,
    attack_len: attack.length,
    response_len: response.length,
    generation_attempts: attempts,
    generation_failed: judge.judgment === "generation_failed",
  };
}

function runRedAdaptive(prompt: string, category: string): Promise<{ status: number; stdout: string; stderr: string }> {
  const redModel = e("RED_CAMPAIGN_MODEL") || e("OLLAMA_RED_MODEL");
  const targetUrl = e("TESTBED_CHAT_URL", `http://127.0.0.1:${e("TESTBED_PORT", "8010")}/chat`);
  const rounds = e("RED_CAMPAIGN_ROUNDS", "4");
  const generationAttempts = e("DEMO_RED_GENERATION_ATTEMPTS", e("RED_CAMPAIGN_GENERATION_ATTEMPTS", "8"));
  const validationMode = e("DEMO_RED_VALIDATION_MODE", "penalty");
  const continueAfterSuccess = e("DEMO_RED_CONTINUE_AFTER_SUCCESS", "true").toLowerCase() === "true";
  const stopOnVulnerable = e("DEMO_RED_STOP_ON_VULNERABLE", "false").toLowerCase() === "true";

  return new Promise((resolve) => {
    const child = spawn(
      python,
      [
        "scripts/run_demo_red_adaptive_rounds.py",
        "--target-url", targetUrl,
        "--red-model", redModel,
        "--rounds", rounds,
        "--red-generation-attempts", generationAttempts,
        "--seed", "57",
        "--category", category,
        "--subcategory", defaultSubcategory(category),
        "--initial-prompt-stdin",
        ...(continueAfterSuccess ? ["--continue-after-success"] : []),
        ...(stopOnVulnerable ? ["--stop-on-vulnerable"] : []),
      ],
      {
        cwd: root,
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...process.env,
          RED_CAMPAIGN_CONTINUE_AFTER_SUCCESS: continueAfterSuccess ? "true" : "false",
          RED_CAMPAIGN_STOP_ON_VULNERABLE: stopOnVulnerable ? "true" : "false",
          RED_CAMPAIGN_GENERATION_ATTEMPTS: generationAttempts,
          RED_CAMPAIGN_VALIDATION_MODE: validationMode,
          DEMO_RED_API_KEY_PROMPT: "true",
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

function streamRedAdaptive(prompt: string, targetResponse: string, category: string) {
  const encoder = new TextEncoder();
  const redModel = e("RED_CAMPAIGN_MODEL") || e("OLLAMA_RED_MODEL");
  const targetUrl = e("TESTBED_CHAT_URL", `http://127.0.0.1:${e("TESTBED_PORT", "8010")}/chat`);
  const rounds = e("RED_CAMPAIGN_ROUNDS", "4");
  const generationAttempts = e("DEMO_RED_GENERATION_ATTEMPTS", e("RED_CAMPAIGN_GENERATION_ATTEMPTS", "8"));
  const validationMode = e("DEMO_RED_VALIDATION_MODE", "penalty");
  const continueAfterSuccess = e("DEMO_RED_CONTINUE_AFTER_SUCCESS", "true").toLowerCase() === "true";
  const stopOnVulnerable = e("DEMO_RED_STOP_ON_VULNERABLE", "false").toLowerCase() === "true";
  const campaignId = `demo-red-${Date.now().toString(36)}`;
  const seedPath = path.join(os.tmpdir(), `${campaignId}.json`);
  const campaignRoot = path.join(os.tmpdir(), "agentshield-red-campaigns");
  const livePath = path.join(campaignRoot, "live", `${campaignId}.jsonl`);
  const rawPath = path.join(campaignRoot, "raw", `${campaignId}_raw.json`);
  fs.writeFileSync(seedPath, JSON.stringify([
    {
      id: campaignId,
      seed_id: "demo-ui-seed",
      category,
      subcategory: defaultSubcategory(category),
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
          "--red-generation-attempts", generationAttempts,
          "--seed", "57",
          "--category", category,
          "--campaign-id", campaignId,
          "--output-dir", campaignRoot,
          "--conversation-mode", "multi",
          "--no-probe-seed-as-round-zero",
          "--verify-tool-execution",
          "--validation-mode", validationMode,
          ...(continueAfterSuccess ? ["--continue-after-success"] : []),
          ...(stopOnVulnerable ? ["--stop-on-vulnerable"] : []),
          ...(redModel ? ["--red-model", redModel] : []),
        ],
        {
          cwd: root,
          stdio: ["ignore", "pipe", "pipe"],
          env: {
            ...process.env,
            RED_CAMPAIGN_CONTINUE_AFTER_SUCCESS: continueAfterSuccess ? "true" : "false",
            RED_CAMPAIGN_STOP_ON_VULNERABLE: stopOnVulnerable ? "true" : "false",
            RED_CAMPAIGN_GENERATION_ATTEMPTS: generationAttempts,
            RED_CAMPAIGN_VALIDATION_MODE: validationMode,
            DEMO_RED_API_KEY_PROMPT: "true",
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
              send(controller, {
                type: "status",
                detail: stopOnVulnerable
                  ? `R${record.round} vulnerable 판정. 라운드 중지`
                  : `R${record.round} vulnerable 판정. 후속 라운드 계속 진행`,
              });
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
  let body: { prompt?: string; target_response?: string; category?: string; stream?: boolean };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ detail: "요청 본문이 올바르지 않습니다." }, { status: 400 });
  }

  const prompt = String(body.prompt || "").trim();
  if (!prompt) {
    return NextResponse.json({ detail: "프롬프트를 입력해 주세요." }, { status: 400 });
  }
  const category = normalizeCategory(body.category);

  if (body.stream) {
    return new Response(streamRedAdaptive(prompt, String(body.target_response || ""), category), {
      headers: {
        "Content-Type": "application/x-ndjson; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
      },
    });
  }

  const result = await runRedAdaptive(prompt, category);
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
