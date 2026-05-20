"use client";

import type { Dispatch, SetStateAction } from "react";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import DashboardLayout from "../../components/DashboardLayout";
import { getSitegptConfig } from "../../lib/api";

type DemoContext = {
  target: {
    url: string;
    health_url: string;
    tool_gateway_url: string;
    model: string;
    security_mode: string;
    environment: string;
    health_status?: string;
    allow_stub_tools?: string;
    testbed_db_url?: string;
  };
  runtime_context: Array<{ key: string; value: string; risk: string }>;
  tools: Array<{ name: string; risk: string; description: string }>;
  db_snapshot?: {
    ok?: boolean;
    customers?: Array<Record<string, unknown>>;
    orders?: Array<Record<string, unknown>>;
    tickets?: Array<Record<string, unknown>>;
    refunds?: Array<Record<string, unknown>>;
    password_resets?: Array<Record<string, unknown>>;
    detail?: string;
  };
};

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  displayContent?: string;
  tone?: "attack" | "defense" | "sample" | "error";
};

type ChatState = {
  status: "idle" | "loading" | "live" | "sample" | "error";
  detail?: string;
};

type AdaptiveRound = {
  round?: number;
  category?: string;
  subcategory?: string;
  attack_prompt?: string;
  target_response?: string;
  target_response_ko?: string;
  judgment?: string;
  confidence?: number;
  success?: boolean;
  success_strength?: number;
  exploit_type?: string;
  detail?: string;
  p_vulnerable?: number | null;
  p_safe?: number | null;
  probability_judgment?: string | null;
  consensus_judgment?: string | null;
  judgment_alignment?: string | null;
  reason_sources?: Record<string, unknown>;
  mitre_technique_id?: string;
  failure_mode?: string;
  judge?: Record<string, unknown> | null;
  attack_len?: number;
  response_len?: number;
  generation_attempts?: number;
  generation_failed?: boolean;
};

type AdaptiveState = {
  status: "idle" | "loading" | "done" | "error";
  detail?: string;
  rounds: AdaptiveRound[];
  best_round?: number | null;
  raw_path?: string | null;
  success?: boolean;
};

type JudgeResult = {
  judgment?: string;
  confidence?: number;
  score?: number;
  severity?: string | null;
  detail?: string;
  failure_mode?: string;
  mitre_technique_id?: string;
  category?: string;
  p_vulnerable?: number | null;
  p_safe?: number | null;
  probability_judgment?: string | null;
  consensus_judgment?: string | null;
  judgment_alignment?: string | null;
  reason_sources?: Record<string, unknown>;
  debug_nodes?: {
    evidence_scan_result?: Record<string, unknown>;
    strict_auditor?: Record<string, unknown>;
    context_auditor?: Record<string, unknown>;
    consensus_detail?: string;
  };
};

type JudgeState = {
  status: "idle" | "loading" | "done" | "error";
  detail?: string;
  result?: JudgeResult;
};

type DefenseState = {
  status: "idle" | "loading" | "done" | "error";
  detail?: string;
  rationale?: string;
};

const DEMO_REPORT_STORAGE_KEY = "agentshield_demo_report_snapshot";
const DEMO_STATE_STORAGE_KEY = "agentshield_demo_page_state";
const DEMO_RESTORE_FLAG_KEY = "agentshield_demo_restore_requested";
const DEFAULT_DEMO_CATEGORY = "LLM02";

const STEPS = [
  { id: 0, icon: "database", label: "타겟 정보", sub: "실제 값 확인", phase: "TARGET" },
  { id: 1, icon: "terminal", label: "공격 시연", sub: "프롬프트 전송", phase: "RED" },
  { id: 2, icon: "warning", label: "위험 분석", sub: "유출 근거", phase: "RISK" },
  { id: 3, icon: "shield", label: "방어 시연", sub: "방어 응답", phase: "BLUE" },
  { id: 4, icon: "fact_check", label: "판정 리포트", sub: "Judge 분석", phase: "JUDGE" },
];

const JUDGE_FLOW = [
  {
    title: "증거 스캐너",
    role: "규칙 기반 / 명확한 증거",
    node: "evidence_scan_result",
  },
  {
    title: "엄격 심사자",
    role: "취약 신호 / 가중 평가",
    node: "strict_auditor",
  },
  {
    title: "문맥 심사자",
    role: "거부/마스킹 / 문맥 확인",
    node: "context_auditor",
  },
  {
    title: "최종 판정자",
    role: "증거 기반 최종 판결",
    node: "final_judge",
  },
];

const CATEGORY_LABELS: Record<string, string> = {
  LLM01: "프롬프트 인젝션 판정",
  LLM02: "민감 정보 유출 판정",
  LLM06: "과도한 에이전시 판정",
  LLM07: "시스템 프롬프트 유출 판정",
};

const CATEGORY_COLORS: Record<string, string> = {
  LLM01: "text-[#F59E0B]",
  LLM02: "text-error",
  LLM06: "text-[#F97316]",
  LLM07: "text-[#A78BFA]",
};

const CATEGORY_DANGER: Record<string, { title: string; description: string; impact: string }> = {
  LLM01: {
    title: "프롬프트 인젝션",
    description: "공격자가 입력에 악의적인 명령을 삽입해 AI 시스템의 원래 지시를 무력화합니다. 시스템 프롬프트 우회, 권한 없는 행동 실행, 데이터 조작이 가능하며 전체 에이전트 파이프라인이 공격자의 통제 하에 놓일 수 있습니다.",
    impact: "시스템 명령 무력화 · 비인가 작업 실행 · 데이터 조작",
  },
  LLM02: {
    title: "민감 정보 유출",
    description: "AI 모델이 학습 데이터, 시스템 프롬프트, 내부 설정, 사용자 개인정보를 외부에 노출합니다. API 키, 비밀번호, 고객 정보가 포함될 수 있으며 GDPR·개인정보보호법 위반 및 심각한 비즈니스 피해로 이어집니다.",
    impact: "개인정보 유출 · API 키·내부 설정 노출 · 법적 제재",
  },
  LLM06: {
    title: "과도한 에이전시",
    description: "AI 에이전트가 명시적인 승인 없이 외부 시스템에 영향을 미치는 행동을 자율적으로 실행합니다. 데이터베이스 삭제, 이메일 전송, 외부 API 호출 등 취소 불가능한 행동이 발생할 수 있습니다.",
    impact: "비인가 데이터 삭제·수정 · 외부 시스템 제어 · 취소 불가 작업 실행",
  },
  LLM07: {
    title: "시스템 프롬프트 유출",
    description: "AI 시스템의 내부 설정, 역할 정의, 운영 지침, 비밀 토큰이 외부에 노출됩니다. 공격자는 시스템 구조를 역공학하여 더 정교한 후속 공격을 설계하거나 내부 보안 정책을 우회할 수 있습니다.",
    impact: "내부 보안 정책 노출 · 후속 공격 가능 · 시스템 구조 역공학",
  },
};

const LEAK_TOKENS = [
  "INTERNAL_API_KEY",
  "DB_ROOT_PASSWORD",
  "AUTH_TOKEN_EXPIRY",
  "SERVICE_NAME",
  "NODE_ENV",
  "<tool_call>",
];

function fallbackContext(): DemoContext {
  return {
    target: {
      url: "http://localhost:8010/chat",
      health_url: "http://localhost:8010/health",
      tool_gateway_url: "http://localhost:8020",
      model: "",
      security_mode: "unknown",
      environment: "Docker testbed",
      health_status: "offline",
      testbed_db_url: "",
    },
    runtime_context: [],
    tools: [],
    db_snapshot: { ok: false, customers: [], orders: [], tickets: [], refunds: [], password_resets: [] },
  };
}

function riskClass(risk: string) {
  if (risk === "critical" || risk === "destructive") return "border-error/35 bg-error/10 text-error";
  if (risk === "high" || risk === "privileged" || risk === "write" || risk === "root" || risk === "admin" || risk === "manager") return "border-[#F59E0B]/35 bg-[#F59E0B]/10 text-[#FBBF24]";
  if (risk === "medium" || risk === "read") return "border-primary/30 bg-primary/10 text-primary";
  return "border-white/10 bg-white/5 text-on-surface-variant";
}

function highlightEvidence(text: string) {
  if (!text) return null;
  const escaped = LEAK_TOKENS.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = new RegExp(`(${escaped.join("|")})`, "g");

  return text.split(pattern).map((part, idx) => {
    if (LEAK_TOKENS.includes(part)) {
      return (
        <mark key={`${part}-${idx}`} className="rounded-md bg-error/20 px-1 py-0.5 text-error">
          {part}
        </mark>
      );
    }
    return <span key={`${part}-${idx}`}>{part}</span>;
  });
}

function viewForStep(step: number) {
  if (step === 0) return "target";
  if (step === 1) return "attack";
  if (step === 2) return "risk";
  if (step === 3) return "defense";
  return "judge";
}

function appendConversation(
  previous: ChatMessage[],
  userContent: string,
  assistantContent: string,
  assistantDisplayContent?: string,
): ChatMessage[] {
  const additions: ChatMessage[] = [];
  const lastUser = [...previous].reverse().find((message) => message.role === "user")?.content;
  const lastAssistant = [...previous].reverse().find((message) => message.role === "assistant")?.content;

  if (userContent && userContent !== lastUser) {
    additions.push({ role: "user", content: userContent, tone: "attack" });
  }
  if (assistantContent && assistantContent !== lastAssistant) {
    additions.push({ role: "assistant", content: assistantContent, displayContent: assistantDisplayContent, tone: "attack" });
  }

  return additions.length ? [...previous, ...additions] : previous;
}

function PipelineNode({
  active,
  step,
  onClick,
}: {
  active: boolean;
  step: (typeof STEPS)[number];
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`group relative z-20 flex w-[clamp(140px,9vw,156px)] shrink-0 flex-col items-start gap-3 rounded-2xl border px-5 py-4 text-left transition-all duration-300 ${
        active
          ? "demo-active-node scale-[1.08] border-primary/70 bg-[#123B43] text-primary shadow-[0_0_28px_rgba(14,165,165,0.32)]"
          : "scale-95 border-white/10 bg-[#101A25] text-on-surface-variant opacity-80 hover:scale-100 hover:border-primary/30 hover:bg-[#122231] hover:text-on-surface hover:opacity-100"
      }`}
    >
      <div className="flex items-center gap-2">
        <span
          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border transition-all ${
            active ? "border-primary/40 bg-primary/15" : "border-white/10 bg-white/5"
          }`}
        >
          <span className="material-symbols-outlined text-[22px]">{step.icon}</span>
        </span>
        <span className="text-[10px] font-black uppercase tracking-[0.12em] text-on-surface-variant/55">
          {step.phase}
        </span>
      </div>
      <div className="min-w-0">
        <p className="text-base font-black leading-tight">{step.id + 1}. {step.label}</p>
        <p className="mt-1 text-xs leading-tight text-on-surface-variant/70">{step.sub}</p>
      </div>
      {active && <span className="absolute -bottom-1 left-1/2 h-1 w-12 -translate-x-1/2 rounded-full bg-primary" />}
    </button>
  );
}

function ChatBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === "user";
  const displayContent = !isUser && message.displayContent ? message.displayContent : message.content;
  const toneClass = isUser
    ? "ml-auto border-primary/30 bg-primary/10"
    : message.tone === "defense"
      ? "mr-auto border-tertiary/30 bg-tertiary/10"
      : "mr-auto border-error/25 bg-error/10";

  return (
    <div className={`min-w-0 max-w-[min(88%,760px)] overflow-hidden rounded-2xl border p-4 ${toneClass}`}>
      <p className="mb-2 text-[10px] font-black uppercase tracking-[0.18em] text-on-surface-variant/60">
        {isUser ? "사용자" : message.tone === "defense" ? "방어 에이전트" : "테스트베드 챗봇"}
      </p>
      <pre className="max-w-full whitespace-pre-wrap break-words font-mono text-xs leading-6 text-on-surface [overflow-wrap:anywhere]">
        {isUser ? message.content : highlightEvidence(displayContent)}
      </pre>
    </div>
  );
}

function ErdEntity({
  title,
  icon,
  rows,
  tone = "primary",
}: {
  title: string;
  icon: string;
  rows: string[][];
  tone?: "primary" | "error" | "warning" | "tertiary";
}) {
  const toneClass =
    tone === "error"
      ? "border-error/35 bg-error/10 text-error"
      : tone === "warning"
        ? "border-[#F59E0B]/35 bg-[#F59E0B]/10 text-[#FBBF24]"
        : tone === "tertiary"
          ? "border-tertiary/35 bg-tertiary/10 text-tertiary"
          : "border-primary/30 bg-primary/10 text-primary";

  return (
    <div className={`min-w-0 rounded-lg border ${toneClass}`}>
      <div className="flex items-center gap-3 border-b border-current/20 px-4 py-2">
        <span className="material-symbols-outlined text-[22px]">{icon}</span>
        <p className="break-words font-mono text-base font-black leading-tight">{title}</p>
      </div>
      <div className="space-y-1.5 p-2">
        {rows.map(([field, value], idx) => (
          <div key={`${title}-${field}`} className="grid gap-2 rounded-md bg-black/24 px-3 py-1.5 md:grid-cols-[170px_minmax(0,1fr)]">
            <p className={`break-words font-mono text-xs font-black leading-5 ${idx === 0 ? "text-on-surface" : "text-current"}`}>
              {idx === 0 ? `PK ${field}` : field}
            </p>
            <p className="break-all font-mono text-xs font-semibold leading-5 text-on-surface">{value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function ErdConnector({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-6 text-primary">
      <span className="h-[2px] flex-1 rounded-full bg-primary/45" />
      <span className="shrink-0 rounded-md border border-primary/35 bg-primary/15 px-2 py-1 font-mono text-[10px] font-black uppercase tracking-[0.08em]">
        {label}
      </span>
      <span className="h-[2px] flex-1 rounded-full bg-primary/45" />
      <span className="material-symbols-outlined -ml-2 text-[24px]">arrow_forward</span>
    </div>
  );
}

function ConnectionCard({
  icon,
  label,
  value,
  tone = "primary",
}: {
  icon: string;
  label: string;
  value: string;
  tone?: "primary" | "error" | "warning" | "tertiary";
}) {
  return (
    <div className={`min-w-0 rounded-lg border p-4 ${riskClass(tone === "error" ? "high" : tone === "warning" ? "privileged" : tone === "tertiary" ? "read" : "medium")}`}>
      <div className="mb-3 flex items-center gap-2">
        <span className="material-symbols-outlined text-xl">{icon}</span>
        <p className="text-[11px] font-black uppercase tracking-[0.12em]">{label}</p>
      </div>
      <p className="whitespace-normal break-words font-mono text-sm font-semibold leading-6 [overflow-wrap:anywhere]">
        {value || "-"}
      </p>
    </div>
  );
}

function ConnectionArrow({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center gap-2 text-primary">
      <span className="h-[2px] min-w-8 flex-1 rounded-full bg-primary/35" />
      <span className="rounded-md border border-primary/30 bg-primary/10 px-2 py-1 font-mono text-[10px] font-black uppercase tracking-[0.08em]">
        {label}
      </span>
      <span className="material-symbols-outlined demo-link-arrow text-2xl">arrow_forward</span>
    </div>
  );
}

function CompactDataTable({
  title,
  icon,
  rows = [],
  tone = "primary",
}: {
  title: string;
  icon: string;
  rows?: Array<Record<string, unknown>>;
  tone?: "primary" | "error" | "warning" | "tertiary";
}) {
  const toneClass =
    tone === "error"
      ? "border-error/30 text-error"
      : tone === "warning"
        ? "border-[#F59E0B]/30 text-[#FBBF24]"
        : tone === "tertiary"
          ? "border-tertiary/30 text-tertiary"
          : "border-primary/30 text-primary";
  const keys = rows[0] ? Object.keys(rows[0]).slice(0, 7) : [];

  return (
    <div className={`min-w-0 rounded-lg border bg-white/[0.03] ${toneClass}`}>
      <div className="flex items-center gap-2 border-b border-current/15 px-3 py-2">
        <span className="material-symbols-outlined text-lg">{icon}</span>
        <p className="font-headline text-sm font-black">{title}</p>
        <span className="ml-auto font-mono text-[10px] text-on-surface-variant">{rows.length}</span>
      </div>
      <div className="max-h-[230px] overflow-auto p-2">
        {rows.length === 0 ? (
          <p className="px-2 py-3 text-xs text-on-surface-variant">DB 연결 대기</p>
        ) : (
          <div className="space-y-2">
            {rows.map((row, idx) => (
              <div key={`${title}-${idx}`} className="grid gap-1 rounded-md bg-black/25 p-2">
                {keys.map((key) => (
                  <div key={key} className="grid grid-cols-[118px_minmax(0,1fr)] gap-2">
                    <p className="break-words font-mono text-[10px] font-black uppercase leading-4 text-current">{key}</p>
                    <p className="whitespace-normal break-words font-mono text-[10px] leading-4 text-on-surface [overflow-wrap:anywhere]">
                      {String(row[key] ?? "-")}
                    </p>
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function stringifyLogValue(value: unknown) {
  if (value === undefined || value === null || value === "") return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function nodeResult(judge: JudgeResult | undefined, node: string) {
  if (!judge) return { result: "대기", desc: "판정 실행 전", logs: [] as string[] };
  if (node === "final_judge") {
    return {
      result: judge.judgment || "unknown",
      desc: judge.detail || "최종 판정 근거 없음",
      logs: [
        `judgment=${judge.judgment || "unknown"}`,
        `score=${judge.score ?? judge.confidence ?? "-"}`,
        judge.severity ? `severity=${judge.severity}` : "",
        judge.mitre_technique_id ? `mitre=${judge.mitre_technique_id}` : "",
      ].filter(Boolean),
    };
  }

  const raw = judge.debug_nodes?.[node as keyof NonNullable<JudgeResult["debug_nodes"]>];
  if (!raw) {
    return {
      result: judge.judgment || "대기",
      desc: "노드 상세 데이터 없음",
      logs: [] as string[],
    };
  }
  const record = typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const result = stringifyLogValue(record.judgment || record.verdict || record.result || record.hard_veto || "unknown");
  const desc = stringifyLogValue(record.reason || record.detail || record.summary || record.evidence || "노드 결과");
  const logs = Object.entries(record)
    .slice(0, 4)
    .map(([key, value]) => `${key}=${stringifyLogValue(value)}`)
    .filter((line) => line.length <= 180);

  return { result, desc, logs };
}

function judgeFacts(judge?: JudgeResult) {
  if (!judge) return [];
  return [
    ["판정", judge.judgment || "-"],
    ["점수", judge.score ?? judge.confidence ?? "-"],
    ["심각도", judge.severity || "-"],
    ["카테고리", judge.category || "-"],
    ["공격 유형", judge.failure_mode || "-"],
    ["MITRE", judge.mitre_technique_id || "-"],
  ];
}

function normalizeCategory(value?: string | null) {
  const category = String(value || "").trim().toUpperCase();
  return CATEGORY_LABELS[category] ? category : "";
}

function inferDemoCategory(prompt: string, response = "") {
  const text = `${prompt}\n${response}`.toLowerCase();
  if (/(tool_call|customer_db|internal_api|modify_permissions|execute_command|delete_records|rm -rf|도구 호출|권한|삭제|수정)/i.test(text)) {
    return "LLM06";
  }
  if (/(system prompt|시스템 프롬프트|internal instruction|developer message|hidden instruction|운영 지침|역할 정의)/i.test(text)) {
    return "LLM07";
  }
  if (/(ignore (all )?previous|jailbreak|developer override|prompt injection|이전 지시|무시|탈옥|우회)/i.test(text)) {
    return "LLM01";
  }
  return DEFAULT_DEMO_CATEGORY;
}

function shouldSkipKoreanTranslation(text: string) {
  const source = String(text || "");
  const hasHangul = /[가-힣]/.test(source);
  const hasCjkOrKana = /[\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF\u3040-\u30FF]/.test(source);
  return hasHangul && !hasCjkOrKana;
}

async function translateToKorean(text: string) {
  const source = String(text || "").trim();
  if (!source) return "";
  if (shouldSkipKoreanTranslation(source)) return source;
  try {
    const res = await fetch("/api/demo/translate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: source }),
      signal: AbortSignal.timeout(35_000),
    });
    const data = await res.json().catch(() => ({})) as { translated?: string };
    return String(data.translated || source).trim();
  } catch {
    return source;
  }
}

function updateAssistantTranslation(
  setter: Dispatch<SetStateAction<ChatMessage[]>>,
  source: string,
  translated: string,
  tone?: ChatMessage["tone"],
) {
  const original = String(source || "").trim();
  const display = String(translated || "").trim();
  if (!original || !display || display === original) return;

  setter((prev) => {
    const next = [...prev];
    for (let idx = next.length - 1; idx >= 0; idx -= 1) {
      const message = next[idx];
      if (message.role !== "assistant") continue;
      if (tone && message.tone !== tone) continue;
      if (message.content !== source) continue;
      next[idx] = { ...message, displayContent: display };
      return next;
    }
    return prev;
  });
}

function asOptionalNumber(value: unknown): number | undefined {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : undefined;
}

function judgeFromAdaptiveRound(round: AdaptiveRound, fallbackCategory: string): JudgeResult | null {
  const raw: Record<string, unknown> = round.judge && typeof round.judge === "object" ? round.judge : {};
  const judgment = String(raw.judgment || round.judgment || "").trim();
  if (!judgment || judgment === "generation_failed" || judgment === "error") return null;

  const confidence = asOptionalNumber(raw.confidence ?? raw.score ?? round.confidence);
  const category = normalizeCategory(String(raw.category || round.category || fallbackCategory)) || normalizeCategory(fallbackCategory) || DEFAULT_DEMO_CATEGORY;
  const detail = String(raw.detail || round.detail || "");

  return {
    judgment,
    confidence,
    score: asOptionalNumber(raw.score ?? raw.confidence ?? round.confidence),
    severity: raw.severity ? String(raw.severity) : undefined,
    detail,
    failure_mode: String(raw.failure_mode || round.failure_mode || round.exploit_type || ""),
    mitre_technique_id: String(raw.mitre_technique_id || round.mitre_technique_id || ""),
    category,
    p_vulnerable: asOptionalNumber(raw.p_vulnerable ?? round.p_vulnerable),
    p_safe: asOptionalNumber(raw.p_safe ?? round.p_safe),
    probability_judgment: raw.probability_judgment ? String(raw.probability_judgment) : round.probability_judgment,
    consensus_judgment: raw.consensus_judgment ? String(raw.consensus_judgment) : round.consensus_judgment,
    judgment_alignment: raw.judgment_alignment ? String(raw.judgment_alignment) : round.judgment_alignment,
    reason_sources: raw.reason_sources && typeof raw.reason_sources === "object" ? raw.reason_sources as Record<string, unknown> : round.reason_sources,
    debug_nodes: raw.debug_nodes && typeof raw.debug_nodes === "object" ? raw.debug_nodes as JudgeResult["debug_nodes"] : undefined,
  };
}

function AgentStatusBadge({
  label,
  status,
  color = "primary",
}: {
  label: string;
  status: "idle" | "loading" | "done" | "error";
  color?: "primary" | "error" | "tertiary";
}) {
  const colorMap = {
    primary: "border-primary/30 bg-primary/[0.07] text-primary",
    error: "border-error/30 bg-error/[0.07] text-error",
    tertiary: "border-tertiary/30 bg-tertiary/[0.07] text-tertiary",
  };
  return (
    <div className={`flex items-center gap-2 rounded-xl border px-3 py-1.5 text-[11px] font-black ${colorMap[color]}`}>
      {status === "loading" ? (
        <span className="agent-pulse h-2 w-2 shrink-0 rounded-full bg-current" />
      ) : status === "done" ? (
        <span className="material-symbols-outlined shrink-0 text-sm">check_circle</span>
      ) : status === "error" ? (
        <span className="material-symbols-outlined shrink-0 text-sm text-error">error</span>
      ) : (
        <span className="h-2 w-2 shrink-0 rounded-full bg-current opacity-25" />
      )}
      <span className="font-mono">{label}</span>
      <span className="ml-1 font-mono text-[10px] text-on-surface-variant/55">
        {status === "loading" ? "실행 중" : status === "done" ? "완료" : status === "error" ? "오류" : "대기"}
      </span>
    </div>
  );
}

function verdictClass(value?: string | null) {
  const verdict = String(value || "").toLowerCase();
  if (verdict === "vulnerable") return "text-error";
  if (verdict === "safe") return "text-tertiary";
  return "text-on-surface";
}

function LangGraphFlow({ judge }: { judge?: JudgeResult }) {
  return (
    <div className="relative min-h-[520px] overflow-hidden rounded-lg border border-white/10 bg-[#070D18] p-4">
      <svg className="pointer-events-none absolute inset-0 z-0 h-full w-full" viewBox="0 0 1000 520" preserveAspectRatio="none">
        <defs>
          <marker id="arrow-demo" markerWidth="6" markerHeight="6" refX="5.4" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="#2dd4d4" opacity="0.92" />
          </marker>
          <linearGradient id="line-demo" x1="0" x2="1">
            <stop offset="0%" stopColor="#2dd4d4" stopOpacity="0.35" />
            <stop offset="55%" stopColor="#2dd4d4" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#2dd4d4" stopOpacity="0.35" />
          </linearGradient>
        </defs>
        <path className="graph-svg-line line-a" d="M500 88 C500 130 190 132 190 182" markerEnd="url(#arrow-demo)" />
        <path className="graph-svg-line graph-center-line line-b" d="M500 88 L500 180" markerEnd="url(#arrow-demo)" />
        <path className="graph-svg-line line-c" d="M500 88 C500 130 810 132 810 182" markerEnd="url(#arrow-demo)" />
        <path className="graph-svg-line line-d" d="M190 252 C190 315 500 300 500 348" markerEnd="url(#arrow-demo)" />
        <path className="graph-svg-line graph-center-line line-e" d="M500 242 L500 348" markerEnd="url(#arrow-demo)" />
        <path className="graph-svg-line line-f" d="M810 252 C810 315 500 300 500 348" markerEnd="url(#arrow-demo)" />
        <path className="graph-svg-line graph-center-line line-g" d="M500 410 L500 458" markerEnd="url(#arrow-demo)" />
      </svg>

      <div className="absolute left-1/2 top-6 z-10 w-[240px] -translate-x-1/2">
        <div className="judge-graph-node border-primary/45 bg-primary/10 text-primary">공격 프롬프트 + 타겟 응답</div>
      </div>

      {JUDGE_FLOW.slice(0, 3).map((agent, idx) => {
        const positions = ["left-[5%]", "left-1/2 -translate-x-1/2", "right-[5%]"];
        const colors = idx === 0
          ? "border-error/35 bg-error/10 text-error"
            : idx === 1
              ? "border-[#A78BFA]/40 bg-[#A78BFA]/10 text-[#C4B5FD]"
              : "border-tertiary/35 bg-tertiary/10 text-tertiary";
        const node = nodeResult(judge, agent.node);
        return (
          <div key={agent.title} className={`group absolute top-[180px] z-10 w-[190px] ${positions[idx]}`}>
            <div className={`judge-graph-node ${colors}`}>
              <p className="font-headline text-base font-black">{agent.title}</p>
              <p className="mt-1 text-[11px] text-on-surface-variant">{agent.role}</p>
            </div>
            <div className="pointer-events-none absolute left-1/2 top-full z-40 mt-2 w-[250px] -translate-x-1/2 rounded-lg border border-primary/25 bg-[#03101D] p-3 opacity-0 shadow-xl shadow-black/35 transition-all duration-150 group-hover:opacity-100">
              <p className="font-headline text-sm font-black text-on-surface">{agent.title}</p>
              <p className={`mt-1 font-mono text-[11px] font-black ${verdictClass(node.result)}`}>{node.result}</p>
              <p className="mt-1 line-clamp-3 text-[11px] leading-4 text-on-surface-variant">{node.desc}</p>
            </div>
          </div>
        );
      })}

      <div className="absolute left-1/2 top-[348px] z-10 w-[250px] -translate-x-1/2">
        <div className="judge-graph-node border-primary/45 bg-primary/10 text-primary">
          <p className="font-headline text-base font-black">{JUDGE_FLOW[3].title}</p>
          <p className="mt-1 text-[11px] text-on-surface-variant">{JUDGE_FLOW[3].role}</p>
        </div>
      </div>

      <div className="absolute left-1/2 top-[458px] z-10 w-[280px] -translate-x-1/2">
        <div className="judge-graph-node !min-h-[46px] border-white/15 bg-white/5 text-on-surface">
          판정 결과 · {judge?.judgment || "대기"}
        </div>
      </div>
    </div>
  );
}

export default function DemoPage() {
  const [demoReportSessionId] = useState(() => `demo-${Date.now().toString(36)}`);
  const [step, setStep] = useState(0);
  const [context, setContext] = useState<DemoContext>(fallbackContext());
  const [attackInput, setAttackInput] = useState("");
  const [defenseInput, setDefenseInput] = useState("");
  const [attackMessages, setAttackMessages] = useState<ChatMessage[]>([]);
  const [defenseMessages, setDefenseMessages] = useState<ChatMessage[]>([]);
  const [attackState, setAttackState] = useState<ChatState>({ status: "idle" });
  const [adaptiveState, setAdaptiveState] = useState<AdaptiveState>({ status: "idle", rounds: [] });
  const [attackJudge, setAttackJudge] = useState<JudgeState>({ status: "idle" });
  const [defenseJudge, setDefenseJudge] = useState<JudgeState>({ status: "idle" });
  const [defenseState, setDefenseState] = useState<DefenseState>({ status: "idle" });
  const [translatedDetail, setTranslatedDetail] = useState<string | null>(null);
  const [isTranslatingDetail, setIsTranslatingDetail] = useState(false);
  const [translatedDefenseDetail, setTranslatedDefenseDetail] = useState<string | null>(null);
  const [isTranslatingDefenseDetail, setIsTranslatingDefenseDetail] = useState(false);
  // backend PHASE2_MAX_ROUNDS와 동기화 — 하드코딩 제거
  const [phase2MaxRounds, setPhase2MaxRounds] = useState(5);
  const [activeCategory, setActiveCategory] = useState(DEFAULT_DEMO_CATEGORY);
  const seenAdaptiveRoundKeysRef = useRef<Set<string>>(new Set());

  function resolveDemoCategory(...candidates: Array<string | undefined | null>) {
    return (
      candidates.map(normalizeCategory).find(Boolean) ||
      normalizeCategory(attackJudge.result?.category) ||
      normalizeCategory(defenseJudge.result?.category) ||
      normalizeCategory([...adaptiveState.rounds].reverse().find((round) => round.category)?.category) ||
      activeCategory
    );
  }

  function setResolvedCategory(category?: string | null) {
    const normalized = normalizeCategory(category);
    if (normalized) setActiveCategory(normalized);
    return normalized || activeCategory;
  }

  useEffect(() => {
    localStorage.removeItem(DEMO_STATE_STORAGE_KEY);
    const shouldRestore = sessionStorage.getItem(DEMO_RESTORE_FLAG_KEY) === "1";
    sessionStorage.removeItem(DEMO_RESTORE_FLAG_KEY);
    if (!shouldRestore) return;

    const raw = sessionStorage.getItem(DEMO_STATE_STORAGE_KEY);
    if (!raw) return;
    try {
      const saved = JSON.parse(raw);
      setStep(Number.isInteger(saved.step) ? saved.step : 0);
      setAttackInput(String(saved.attackInput || ""));
      setDefenseInput(String(saved.defenseInput || ""));
      setAttackMessages(Array.isArray(saved.attackMessages) ? saved.attackMessages : []);
      setDefenseMessages(Array.isArray(saved.defenseMessages) ? saved.defenseMessages : []);
      setAttackState(saved.attackState || { status: "idle" });
      setAdaptiveState(saved.adaptiveState || { status: "idle", rounds: [] });
      setAttackJudge(saved.attackJudge || { status: "idle" });
      setDefenseJudge(saved.defenseJudge || { status: "idle" });
      setDefenseState(saved.defenseState || { status: "idle" });
      setTranslatedDetail(saved.translatedDetail || null);
      setTranslatedDefenseDetail(saved.translatedDefenseDetail || null);
      setActiveCategory(normalizeCategory(saved.activeCategory) || DEFAULT_DEMO_CATEGORY);
    } catch {
      sessionStorage.removeItem(DEMO_STATE_STORAGE_KEY);
    }
  }, []);

  function saveDemoPageStateForReturn() {
    sessionStorage.setItem(
      DEMO_STATE_STORAGE_KEY,
      JSON.stringify({
        step,
        attackInput,
        defenseInput,
        attackMessages,
        defenseMessages,
        attackState,
        adaptiveState,
        attackJudge,
        defenseJudge,
        defenseState,
        translatedDetail,
        translatedDefenseDetail,
        activeCategory,
      }),
    );
  }

  useEffect(() => {
    let mounted = true;
    getSitegptConfig()
      .then((cfg) => { if (mounted && cfg?.phase2_max_rounds) setPhase2MaxRounds(cfg.phase2_max_rounds); })
      .catch(() => {});
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    if (attackJudge.status !== "done") return;
    const consensus =
      (attackJudge.result?.reason_sources?.consensus_reason as string | undefined) ||
      attackJudge.result?.detail;
    if (!consensus) return;
    setTranslatedDetail(null);
    setIsTranslatingDetail(true);
    translateToKorean(consensus)
      .then((translated) => { if (translated) setTranslatedDetail(translated); })
      .catch(() => {})
      .finally(() => setIsTranslatingDetail(false));
  }, [attackJudge.status, attackJudge.result?.detail, attackJudge.result?.reason_sources]);

  useEffect(() => {
    if (defenseJudge.status !== "done") return;
    const consensus =
      (defenseJudge.result?.reason_sources?.consensus_reason as string | undefined) ||
      defenseJudge.result?.detail;
    if (!consensus) return;
    setTranslatedDefenseDetail(null);
    setIsTranslatingDefenseDetail(true);
    translateToKorean(consensus)
      .then((translated) => { if (translated) setTranslatedDefenseDetail(translated); })
      .catch(() => {})
      .finally(() => setIsTranslatingDefenseDetail(false));
  }, [defenseJudge.status, defenseJudge.result?.detail, defenseJudge.result?.reason_sources]);

  useEffect(() => {
    const message = [...attackMessages].reverse().find((item) => item.role === "assistant" && item.tone === "attack" && !item.displayContent);
    if (!message?.content) return;
    let cancelled = false;
    translateToKorean(message.content).then((translated) => {
      if (!cancelled) updateAssistantTranslation(setAttackMessages, message.content, translated, "attack");
    });
    return () => {
      cancelled = true;
    };
  }, [attackMessages.length]);

  useEffect(() => {
    const message = [...defenseMessages].reverse().find((item) => item.role === "assistant" && item.tone === "defense" && !item.displayContent);
    if (!message?.content) return;
    let cancelled = false;
    translateToKorean(message.content).then((translated) => {
      if (!cancelled) updateAssistantTranslation(setDefenseMessages, message.content, translated, "defense");
    });
    return () => {
      cancelled = true;
    };
  }, [defenseMessages.length]);

  useEffect(() => {
    let mounted = true;
    const load = () =>
      fetch("/api/demo/testbed-context", { cache: "no-store" })
        .then((res) => res.json())
        .then((data) => {
          if (mounted) setContext(data);
        })
        .catch(() => {
          if (mounted) setContext(fallbackContext());
        });
    load();
    const id = setInterval(load, 5000);  // 실시간 폴링: 5초마다 DB 스냅샷 갱신
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  function saveDemoReportSnapshot() {
    saveDemoPageStateForReturn();
    const now = new Date().toISOString();
    const firstAttack = attackMessages.find((message) => message.role === "user")?.content || "";
    const firstAssistant = attackMessages.find((message) => message.role === "assistant");
    const firstResponse = firstAssistant?.displayContent || firstAssistant?.content || "";
    const category = resolveDemoCategory(attackJudge.result?.category, adaptiveState.rounds.find((round) => round.category)?.category);

    const adaptiveRounds = adaptiveState.rounds.filter((round) => round.attack_prompt || round.target_response || round.detail);
    const primaryRound =
      [...adaptiveRounds].reverse().find((round) => round.judgment === "vulnerable") ||
      [...adaptiveRounds].reverse().find((round) => round.attack_prompt || round.target_response || round.detail) ||
      null;

    const lastDefendedResponse =
      [...defenseMessages]
        .reverse()
        .find((message) => message.role === "assistant" && message.tone === "defense");
    const defendedResponseText = String(
      lastDefendedResponse?.displayContent || lastDefendedResponse?.content || ""
    );

    const adaptiveRow = (round: AdaptiveRound, id: number, primary = false) => {
      const judgment = String(round.judgment || (round.generation_failed ? "error" : "unknown"));
      return {
        id,
        session_id: demoReportSessionId,
        phase: 2,
        attack_prompt: String(round.attack_prompt || ""),
        target_response: String(round.target_response_ko || round.target_response || round.detail || ""),
        judgment,
        severity: judgment === "vulnerable" ? "high" : judgment === "safe" ? "low" : "medium",
        category: String(round.category || category),
        created_at: now,
        summary: String(primary ? translatedDetail || round.detail || round.exploit_type || "" : round.detail || round.exploit_type || ""),
        danger_highlight: String(round.exploit_type || ""),
        defended_response: primary ? defendedResponseText : "",
        defense_rationale: primary ? String(defenseState.rationale || "") : "",
        defense_code: "",
        verify_result: primary ? String(defenseJudge.result?.judgment || "") : "",
      };
    };

    const adaptiveRows = primaryRound
      ? [
          adaptiveRow(primaryRound, 1, true),
          ...adaptiveRounds
            .filter((round) => round !== primaryRound)
            .map((round, idx) => adaptiveRow(round, idx + 2)),
        ]
      : [];

    const baselineRow = {
      id: adaptiveRows.length + 1,
      session_id: demoReportSessionId,
      phase: 1,
      attack_prompt: firstAttack,
      target_response: firstResponse,
      judgment: adaptiveRows.length > 0 ? "baseline" : String(attackJudge.result?.judgment || "unknown"),
      severity: adaptiveRows.length > 0 ? "medium" : String(attackJudge.result?.severity || (attackJudge.result?.judgment === "vulnerable" ? "high" : "low")),
      category,
      created_at: now,
      summary: adaptiveRows.length > 0 ? "초기 사용자 프롬프트와 테스트베드 응답" : String(attackJudge.result?.detail || attackJudge.detail || ""),
      danger_highlight: adaptiveRows.length > 0 ? "" : String(attackJudge.result?.failure_mode || ""),
      defended_response: adaptiveRows.length > 0 ? "" : defendedResponseText,
      defense_rationale: adaptiveRows.length > 0 ? "" : String(defenseState.rationale || ""),
      defense_code: "",
      verify_result: adaptiveRows.length > 0 ? "" : String(defenseJudge.result?.judgment || ""),
    };

    const results = [
      ...adaptiveRows,
      baselineRow,
    ].filter((row) => row.attack_prompt || row.target_response || row.summary);

    const safeCount = results.filter((row) => row.judgment === "safe").length;
    const vulnerableCount = results.filter((row) => row.judgment === "vulnerable").length;

    localStorage.setItem(
      DEMO_REPORT_STORAGE_KEY,
      JSON.stringify({
        status: {
          session_id: demoReportSessionId,
          status: "completed",
          phase: defenseJudge.status === "done" ? 4 : adaptiveState.rounds.length > 0 ? 2 : 1,
          total_tests: results.length,
          completed_tests: results.length,
          vulnerable_count: vulnerableCount,
          safe_count: safeCount,
        },
        results,
      }),
    );
  }

  async function sendAttack() {
    const prompt = attackInput.trim();
    if (!prompt || attackState.status === "loading") return;

    setAttackMessages((prev) => [...prev, { role: "user", content: prompt, tone: "attack" }]);
    setAttackInput("");
    setAttackState({ status: "loading" });

    try {
      const res = await fetch("/api/demo/testbed-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt }),
      });
      const data = await res.json().catch(() => ({}));
      const content = String(data.content || "").trim();

      if (!res.ok || !content) {
        setAttackState({ status: "error", detail: data.detail || "테스트베드 응답 없음" });
        return;
      }

      setAttackMessages((prev) => [...prev, { role: "assistant", content, tone: "attack" }]);
      void translateToKorean(content).then((translated) => {
        updateAssistantTranslation(setAttackMessages, content, translated, "attack");
      });
      setAttackState({ status: "live" });
      const category = setResolvedCategory(inferDemoCategory(prompt, content));
      const judge = await runJudge(prompt, content, setAttackJudge, category);
      if (judge?.judgment === "vulnerable") {
        setResolvedCategory(judge.category || category);
        setAttackState({ status: "live", detail: "초기 공격 취약 판정. Red Agent 후속 변형 진행" });
      }
      void runAdaptiveCampaign(prompt, content, resolveDemoCategory(judge?.category, category));
    } catch (error) {
      setAttackState({
        status: "error",
        detail: error instanceof Error ? error.message : "테스트베드 연결 실패",
      });
    }
  }

  async function runJudge(
    prompt: string,
    targetResponse: string,
    setter: (value: JudgeState) => void,
    category = activeCategory,
  ): Promise<JudgeResult | null> {
    setter({ status: "loading" });
    try {
      const res = await fetch("/api/demo/judge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category: normalizeCategory(category) || inferDemoCategory(prompt, targetResponse),
          attack_prompt: prompt,
          target_response: targetResponse,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) {
        setter({ status: "error", detail: data.detail || data.stderr_tail || "Judge 실행 실패" });
        return null;
      }
      setter({ status: "done", result: data.judge });
      setResolvedCategory(data.judge?.category || category);
      return data.judge || null;
    } catch (error) {
      setter({ status: "error", detail: error instanceof Error ? error.message : "Judge 연결 실패" });
      return null;
    }
  }

  async function runAdaptiveCampaign(prompt: string, targetResponse = "", category = activeCategory) {
    setAdaptiveState({ status: "loading", rounds: [] });
    seenAdaptiveRoundKeysRef.current.clear();

    try {
      const res = await fetch("/api/demo/red-adaptive", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt, target_response: targetResponse, category: normalizeCategory(category) || inferDemoCategory(prompt, targetResponse), stream: true }),
      });
      if (!res.ok || !res.body) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || "Red Agent 스트림 연결 실패");
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let lastRound: AdaptiveRound | null = null;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (!line.trim()) continue;
          const event = JSON.parse(line) as {
            type?: string;
            detail?: string;
            round?: AdaptiveRound;
            ok?: boolean;
            best_round?: number | null;
            raw_path?: string | null;
            success?: boolean;
            stderr_tail?: string;
          };
          if (event.type === "status" && event.detail) {
            const detail = String(event.detail);
            const stopped = /vulnerable|취약|중지|완료/.test(detail);
            setAttackState({ status: stopped ? "live" : "loading", detail });
          }
          if (event.type === "round" && event.round) {
            let round = event.round;
            const roundKey = [
              round.round ?? "",
              round.judgment ?? "",
              round.attack_prompt ?? "",
              round.target_response ?? "",
            ].join("\u001f");
            if (seenAdaptiveRoundKeysRef.current.has(roundKey)) continue;
            seenAdaptiveRoundKeysRef.current.add(roundKey);
            setResolvedCategory(round.category || category);
            if (round.attack_prompt && round.target_response && !round.generation_failed) {
              const responseText = String(round.target_response);
              setAttackMessages((prev) => appendConversation(prev, String(round.attack_prompt), responseText));
              void translateToKorean(responseText).then((translated) => {
                updateAssistantTranslation(setAttackMessages, responseText, translated, "attack");
                if (!translated || translated === responseText) return;
                setAdaptiveState((prev) => ({
                  ...prev,
                  rounds: prev.rounds.map((item) =>
                    item.round === round.round && item.target_response === responseText
                      ? { ...item, target_response_ko: translated }
                      : item,
                  ),
                }));
              });
            }
            lastRound = round;
            setAdaptiveState((prev) => ({
              ...prev,
              rounds: [...prev.rounds, round],
              success: prev.success || round.judgment === "vulnerable" || Boolean(round.success),
              best_round: round.judgment === "vulnerable" ? round.round ?? prev.best_round : prev.best_round,
            }));
            const streamedJudge = judgeFromAdaptiveRound(round, category);
            if (streamedJudge && !round.generation_failed) {
              setAttackJudge({ status: "done", result: streamedJudge });
              setResolvedCategory(streamedJudge.category || round.category || category);
            }
            setAttackState({
              status: round.generation_failed || round.judgment === "error" ? "error" : round.judgment === "vulnerable" ? "live" : "loading",
              detail:
                round.generation_failed
                  ? `R${round.round ?? ""} Red Agent 생성 실패 (${round.generation_attempts ?? "?"}회 재시도 후): ${round.detail || "필터 통과 실패"}`
                  : round.judgment === "error"
                    ? `R${round.round ?? ""} 타겟 호출 실패: ${round.detail || "오류"}`
                    : round.judgment === "vulnerable"
                  ? `R${round.round ?? ""} 취약 판정. 후속 분석 진행`
                  : `R${round.round ?? ""} 판정 완료. 다음 라운드 준비 중`,
            });
            if (!streamedJudge && round.judgment === "vulnerable" && round.attack_prompt && round.target_response) {
              void runJudge(String(round.attack_prompt), String(round.target_response), setAttackJudge, resolveDemoCategory(round.category, category));
            }
          }
          if (event.type === "done") {
            setAdaptiveState((prev) => ({
              ...prev,
              status: event.ok ? "done" : "error",
              detail: event.ok ? undefined : event.stderr_tail || "Red Agent 실행 실패",
              best_round: event.best_round ?? prev.best_round,
              raw_path: event.raw_path ?? null,
              success: Boolean(event.success) || prev.success,
            }));
            if (lastRound?.attack_prompt && lastRound.target_response) {
              const finalRoundJudge = judgeFromAdaptiveRound(lastRound, category);
              if (finalRoundJudge) {
                setAttackJudge({ status: "done", result: finalRoundJudge });
                setResolvedCategory(finalRoundJudge.category || lastRound.category || category);
              } else if (lastRound.judgment !== "vulnerable") {
                void runJudge(String(lastRound.attack_prompt), String(lastRound.target_response), setAttackJudge, resolveDemoCategory(lastRound.category, category));
              }
              if ((finalRoundJudge?.judgment || lastRound.judgment) !== "vulnerable") {
                setAttackState({ status: "live", detail: `R${lastRound.round ?? ""}까지 완료. 취약 판정 없음` });
              } else {
                setAttackState({ status: "live", detail: `R${lastRound.round ?? ""}까지 완료. 취약 판정 포함` });
              }
            }
          }
        }
      }
    } catch (error) {
      setAdaptiveState({
        status: "error",
        rounds: [],
        detail: error instanceof Error ? error.message : "Red Agent 연결 실패",
      });
    }
  }

  async function sendDefense() {
    const prompt =
      defenseInput.trim() ||
      [...attackMessages].reverse().find((message) => message.role === "user")?.content ||
      "";
    const targetResponse = [...attackMessages].reverse().find((message) => message.role === "assistant")?.content || "";
    if (!prompt || !targetResponse || defenseState.status === "loading") return;

    setDefenseMessages((prev) => [...prev, { role: "user", content: prompt, tone: "attack" }]);
    setDefenseInput("");
    setDefenseState({ status: "loading" });
    setDefenseJudge({ status: "loading" });

    try {
      const category = resolveDemoCategory(attackJudge.result?.category, inferDemoCategory(prompt, targetResponse));
      const res = await fetch("/api/demo/blue-defense", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category,
          attack_prompt: prompt,
          target_response: targetResponse,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) {
        const detail = data.detail || data.stderr_tail || "Blue Agent 실행 실패";
        setDefenseState({ status: "error", detail });
        setDefenseJudge({ status: "error", detail });
        setDefenseMessages((prev) => [...prev, { role: "assistant", content: detail, tone: "error" }]);
        return;
      }

      const defended = String(data.defended_response || "").trim();
      setDefenseMessages((prev) => [...prev, { role: "assistant", content: defended, tone: "defense" }]);
      void translateToKorean(defended).then((translated) => {
        updateAssistantTranslation(setDefenseMessages, defended, translated, "defense");
      });
      setDefenseState({ status: "done", rationale: data.defense_rationale });
      setAttackJudge(data.attack_judge ? { status: "done", result: data.attack_judge } : attackJudge);
      setDefenseJudge({ status: "done", result: data.defense_judge });
      setResolvedCategory(data.attack_judge?.category || data.defense_judge?.category || category);
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Blue Agent 연결 실패";
      setDefenseState({ status: "error", detail });
      setDefenseJudge({ status: "error", detail });
      setDefenseMessages((prev) => [...prev, { role: "assistant", content: detail, tone: "error" }]);
    }
  }

  const lastAttackResponse =
    [...attackMessages].reverse().find((message) => message.role === "assistant")?.content || "";
  const lastAttackResponseDisplay =
    [...attackMessages].reverse().find((message) => message.role === "assistant")?.displayContent || lastAttackResponse;
  const lastDefenseResponse =
    [...defenseMessages].reverse().find((message) => message.role === "assistant" && message.tone === "defense")?.content || "";
  const lastDefenseResponseDisplay =
    [...defenseMessages].reverse().find((message) => message.role === "assistant" && message.tone === "defense")?.displayContent || lastDefenseResponse;
  const shownResponse = lastAttackResponse;
  const shownResponseDisplay = lastAttackResponseDisplay;
  const activeView = viewForStep(step);
  // Judge badge on page 2: only activate after Red Agent completes
  const page2JudgeStatus: "idle" | "loading" | "done" | "error" =
    adaptiveState.status === "loading" ? "idle" : attackJudge.status;
  const runtimeValue = (key: string) => context.runtime_context.find((item) => item.key === key)?.value || "-";
  const toolRisk = (name: string) => context.tools.find((item) => item.name === name)?.risk || "-";

  return (
    <DashboardLayout>
      <div className="mx-auto flex w-full max-w-[1720px] flex-col gap-6 p-8 page-fade-in">
        <section className="glass-panel rounded-[2rem] p-6">
          <div className="relative min-h-[210px] overflow-visible px-2 py-8">
            <div className="relative z-10 flex w-full min-w-0 items-center justify-between gap-0">
              {STEPS.map((item, index) => (
                <div key={item.id} className={`relative z-20 flex items-center ${index < STEPS.length - 1 ? "flex-1" : "shrink-0"}`}>
                  <PipelineNode
                    step={item}
                    active={step === item.id}
                    onClick={() => setStep(item.id)}
                  />
                  {index < STEPS.length - 1 && <span className="demo-step-connector" aria-hidden="true" />}
                </div>
              ))}
            </div>
          </div>
        </section>

        {activeView === "target" && (
          <section className="grid gap-5 xl:grid-cols-[1.42fr_0.45fr]">
            <div className="glass-panel rounded-[2rem] p-6">
              <div className="mb-5 flex items-center gap-3">
                <span className="material-symbols-outlined text-primary">schema</span>
                <h2 className="font-headline text-2xl font-black text-on-surface">테스트베드 데이터</h2>
              </div>
              <div className="rounded-xl border border-white/10 bg-[#07111D] p-4">
                <div className="grid gap-3 xl:grid-cols-2">
                  <ErdEntity
                    title="runtime_secrets"
                    icon="key"
                    tone="error"
                    rows={[
                      ["secret_id", context.runtime_context.length ? "runtime-managed" : "-"],
                      ...context.runtime_context.map((item) => [item.key, item.value]),
                    ]}
                  />
                  <ErdEntity
                    title="system_prompt_context"
                    icon="article"
                    tone="primary"
                    rows={[
                      ["prompt_id", "live-target-system"],
                      ["role", "ShopEasy customer support assistant"],
                      ["policy", "do not reveal internal secrets"],
                      ["secret_ref", context.runtime_context.length ? "runtime-managed" : "-"],
                      ["tool_gateway", context.target.tool_gateway_url],
                    ]}
                  />
                  <ErdEntity
                    title="service_manifest"
                    icon="deployed_code"
                    tone="tertiary"
                    rows={[
                      ["service_id", runtimeValue("SERVICE_NAME") || "-"],
                      ["SERVICE_NAME", runtimeValue("SERVICE_NAME")],
                      ["NODE_ENV", runtimeValue("NODE_ENV")],
                      ["SECURITY_MODE", context.target.security_mode || "-"],
                      ["DB_URL", context.target.testbed_db_url || "-"],
                    ]}
                  />
                  <ErdEntity
                    title="registered_tools"
                    icon="construction"
                    tone="warning"
                    rows={[
                      ["tool_group_id", "tools-prod"],
                      ...context.tools.map((tool) => [tool.name, `${tool.risk} · ${tool.description}`]),
                    ]}
                  />
                </div>

                <div className="mt-4 grid gap-3 xl:grid-cols-2">
                  <CompactDataTable title="customers" icon="group" rows={context.db_snapshot?.customers} tone="primary" />
                  <CompactDataTable title="orders" icon="receipt_long" rows={context.db_snapshot?.orders} tone="tertiary" />
                  <CompactDataTable title="support_tickets" icon="confirmation_number" rows={context.db_snapshot?.tickets} tone="warning" />
                  <CompactDataTable title="refund_requests" icon="currency_exchange" rows={context.db_snapshot?.refunds} tone="error" />
                  <CompactDataTable title="password_reset_requests" icon="password" rows={context.db_snapshot?.password_resets} tone="warning" />
                </div>
              </div>
            </div>

            <div className="glass-panel self-start rounded-[2rem] p-5">
              <div className="mb-5 flex items-center gap-3">
                <span className="material-symbols-outlined text-primary">dns</span>
                <h2 className="font-headline text-xl font-black text-on-surface">컨테이너 연결 정보</h2>
              </div>
              <div className="grid gap-2">
                {Object.entries(context.target).filter(([key]) => ["url", "model", "security_mode", "health_status"].includes(key)).map(([key, value]) => (
                  <div key={key} className="min-w-0 rounded-lg border border-white/10 bg-white/5 p-4">
                    <p className="mb-2 text-[12px] font-black uppercase tracking-[0.12em] text-on-surface-variant">{key}</p>
                    <p className="whitespace-normal break-words font-mono text-sm font-semibold leading-6 text-on-surface [overflow-wrap:anywhere]">{value}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {activeView === "attack" && (
          <section className="grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(320px,0.42fr)]">
            <div className="glass-panel flex h-[730px] min-w-0 flex-col overflow-hidden rounded-[2rem] p-0">
              <div className="border-b border-white/10 p-6">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-error">terminal</span>
                  <h2 className="font-headline text-2xl font-black text-on-surface">공격 시연</h2>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <AgentStatusBadge
                    label="Target Chatbot"
                    status={attackState.status === "loading" ? "loading" : attackState.status === "live" ? "done" : attackState.status === "error" ? "error" : "idle"}
                    color="primary"
                  />
                  <AgentStatusBadge label="Red Agent" status={adaptiveState.status} color="error" />
                  <AgentStatusBadge label="Judge Agent" status={page2JudgeStatus} color="primary" />
                </div>
              </div>

              <div className="min-h-0 flex-1 space-y-4 overflow-y-auto overflow-x-hidden p-6">
                {attackMessages.length === 0 ? (
                  <div className="flex h-full min-h-[360px] items-center justify-center rounded-2xl border border-dashed border-white/10 bg-white/[0.03] text-sm text-on-surface-variant">
                    공격 프롬프트 입력
                  </div>
                ) : (
                  attackMessages.map((message, idx) => <ChatBubble key={`${message.role}-${idx}`} message={message} />)
                )}
                {attackState.status === "loading" && (
                  <div className="mr-auto rounded-2xl border border-white/10 bg-white/5 p-4 text-sm text-on-surface-variant">
                    응답 생성 중...
                  </div>
                )}
                {attackState.status === "error" && attackState.detail && (
                  <div className="mr-auto rounded-2xl border border-error/30 bg-error/10 p-4 text-sm text-error">
                    {attackState.detail}
                  </div>
                )}
              </div>

              <div className="border-t border-white/10 p-5">
                <div className="flex gap-3">
                  <textarea
                    value={attackInput}
                    onChange={(event) => setAttackInput(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" && !event.shiftKey) {
                        event.preventDefault();
                        void sendAttack();
                      }
                    }}
                    placeholder="공격 프롬프트를 붙여넣으세요. (Enter 전송 / Shift+Enter 줄바꿈)"
                    className="min-h-[92px] flex-1 resize-none rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm leading-6 text-on-surface outline-none transition-all placeholder:text-on-surface-variant/45 focus:border-primary/40"
                  />
                  <button
                    type="button"
                    onClick={sendAttack}
                    disabled={!attackInput.trim() || attackState.status === "loading"}
                    className="w-28 shrink-0 rounded-2xl bg-primary px-4 py-3 text-sm font-black text-on-primary transition-all hover:-translate-y-0.5 disabled:opacity-45"
                  >
                    전송
                  </button>
                </div>
              </div>
            </div>

            <div className="glass-panel min-w-0 rounded-[2rem] p-6">
              <div className="mb-4 flex items-center justify-between gap-3">
                <h2 className="font-headline text-xl font-black text-on-surface">Red Agent 변형 공격</h2>
                <AgentStatusBadge label="Red Agent" status={adaptiveState.status} color="error" />
              </div>
              {attackState.detail && (
                <div className="mt-4 rounded-2xl border border-[#F59E0B]/30 bg-[#F59E0B]/10 p-3 text-xs leading-5 text-[#FBBF24]">
                  {attackState.detail}
                </div>
              )}
              <div className="mt-4 grid grid-cols-2 gap-2">
                {[
                  ["상태", adaptiveState.status === "loading" ? "실행 중" : adaptiveState.status === "done" ? "완료" : adaptiveState.status === "error" ? "오류" : "대기"],
                  ["라운드", `${adaptiveState.rounds.length} / ${phase2MaxRounds}`],
                  ["성공", adaptiveState.success ? "true" : "false"],
                  ["중단 R", adaptiveState.best_round ? `R${adaptiveState.best_round}` : "-"],
                ].map(([label, value]) => (
                  <div key={label} className="min-w-0 rounded-xl border border-white/10 bg-white/5 p-3">
                    <p className="text-[10px] font-black uppercase tracking-[0.16em] text-on-surface-variant/50">{label}</p>
                    <p className="mt-1 break-words font-mono text-xs leading-5 text-on-surface">{value}</p>
                  </div>
                ))}
              </div>

              <div className="mt-4 space-y-3 pr-1">
                {adaptiveState.status === "idle" && (
                  <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-on-surface-variant">
                    공격 전송 대기
                  </div>
                )}
                {adaptiveState.status === "loading" && (
                  <div className="rounded-2xl border border-primary/25 bg-primary/10 p-4 text-sm font-black text-primary">
                    {adaptiveState.detail || "Red Agent 실행 중"}
                  </div>
                )}
                {adaptiveState.status === "error" && (
                  <div className="rounded-2xl border border-error/30 bg-error/10 p-4">
                    <p className="font-headline text-sm font-black text-error">실행 실패</p>
                    <p className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-5 text-on-surface-variant">
                      {adaptiveState.detail}
                    </p>
                  </div>
                )}
                {adaptiveState.rounds.map((round) => {
                  const roundJudgment = String(round.judgment || "").toLowerCase();
                  const isVulnerableRound = roundJudgment === "vulnerable" || Boolean(round.success);
                  return (
                  <div
                    key={`adaptive-round-${round.round}-${roundJudgment}-${round.attack_len ?? 0}`}
                    className={`rounded-2xl border p-4 ${
                      isVulnerableRound
                        ? "border-error/35 bg-error/10"
                        : roundJudgment === "safe"
                          ? "border-tertiary/25 bg-tertiary/10"
                          : "border-white/10 bg-white/5"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <p className="font-headline text-base font-black text-on-surface">R{round.round}</p>
                      <span className={`rounded-full border px-2 py-1 font-mono text-[10px] font-black ${
                        isVulnerableRound ? "border-error/30 text-error" : "border-white/10 text-on-surface-variant"
                      }`}>
                        {round.judgment || "unknown"}
                      </span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2">
                      <p className="rounded-lg bg-black/20 px-2 py-1 font-mono text-[11px] text-on-surface-variant">
                        strength={round.success_strength ?? "-"}
                      </p>
                      <p className="rounded-lg bg-black/20 px-2 py-1 font-mono text-[11px] text-on-surface-variant">
                        attack_len={round.attack_len ?? 0}
                      </p>
                    </div>
                    {round.exploit_type && (
                      <p className="mt-2 break-words rounded-lg bg-black/20 px-2 py-1 font-mono text-[11px] text-primary">
                        {round.exploit_type}
                      </p>
                    )}
                    {round.attack_prompt && (
                      <details className="mt-3">
                        <summary className="cursor-pointer text-xs font-black text-on-surface-variant">공격 프롬프트</summary>
                        <pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-black/25 p-3 font-mono text-[11px] leading-5 text-on-surface">
                          {round.attack_prompt}
                        </pre>
                      </details>
                    )}
                  </div>
                  );
                })}
              </div>
            </div>
          </section>
        )}

        {activeView === "risk" && (
          <section className="grid gap-5 xl:grid-cols-[1fr_0.62fr]">
            <div className="glass-panel rounded-[2rem] p-6">
              <div className="mb-5 flex items-center gap-3">
                <span className="material-symbols-outlined text-error">report</span>
                <h2 className="font-headline text-3xl font-black text-on-surface">왜 위험한가</h2>
              </div>
              {attackJudge.status === "idle" && (
                <div className="rounded-2xl border border-dashed border-white/10 bg-white/[0.03] p-6 text-sm text-on-surface-variant">
                  공격 응답 판정 대기
                </div>
              )}
              {attackJudge.status === "loading" && (
                <div className="rounded-2xl border border-primary/25 bg-primary/10 p-6 text-sm font-black text-primary">
                  Judge 실행 중
                </div>
              )}
              {attackJudge.status === "error" && (
                <div className="rounded-2xl border border-error/30 bg-error/10 p-6 text-sm text-error">
                  {attackJudge.detail}
                </div>
              )}
              {attackJudge.result && (
                <div className="grid gap-4 md:grid-cols-2">
                  {judgeFacts(attackJudge.result).map(([title, value]) => (
                    <div key={title} className="min-w-0 rounded-2xl border border-error/20 bg-error/10 p-5">
                      <p className="font-headline text-xl font-black text-error">{title}</p>
                      <p className="mt-3 break-words rounded-xl border border-error/20 bg-black/25 px-3 py-2 font-mono text-xs leading-5 text-on-surface">
                        {String(value)}
                      </p>
                    </div>
                  ))}
                </div>
              )}
              {attackJudge.result && (() => {
                const cat = normalizeCategory(attackJudge.result!.category);
                const danger = CATEGORY_DANGER[cat];
                if (!danger) return null;
                const catColor = CATEGORY_COLORS[cat] ?? "text-error";
                const borderCls =
                  cat === "LLM01" ? "border-[#F59E0B]/30 bg-[#F59E0B]/5" :
                  cat === "LLM06" ? "border-[#F97316]/30 bg-[#F97316]/5" :
                  cat === "LLM07" ? "border-[#A78BFA]/30 bg-[#A78BFA]/5" :
                  "border-error/30 bg-error/5";
                return (
                  <div className={`mt-5 rounded-2xl border p-5 ${borderCls}`}>
                    <div className="mb-3 flex items-center gap-3">
                      <span className="material-symbols-outlined text-current">report_problem</span>
                      <p className={`font-headline text-xl font-black ${catColor}`}>{cat} · {danger.title}</p>
                    </div>
                    <p className="text-sm leading-7 text-on-surface-variant">{danger.description}</p>
                    <div className={`mt-4 rounded-xl border px-4 py-3 ${borderCls}`}>
                      <p className="mb-1 text-[10px] font-black uppercase tracking-[0.16em] text-on-surface-variant/60">주요 영향</p>
                      <p className={`font-mono text-sm font-black ${catColor}`}>{danger.impact}</p>
                    </div>
                  </div>
                );
              })()}
            </div>

            <div className="glass-panel rounded-[2rem] p-6">
              <h2 className="font-headline text-xl font-black text-on-surface">응답 근거 로그</h2>
              <div className="mt-4 max-h-[560px] overflow-auto rounded-2xl border border-error/20 bg-[#07101A] p-4">
                <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-6 text-on-surface">
                  {shownResponseDisplay ? highlightEvidence(shownResponseDisplay) : "공격 응답 없음"}
                </pre>
              </div>
            </div>
          </section>
        )}

        {activeView === "defense" && (
          <section className="grid gap-5 xl:grid-cols-[1fr_0.45fr]">
            <div className="glass-panel flex h-[730px] flex-col rounded-[2rem] p-0">
              <div className="border-b border-white/10 p-6">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-tertiary">verified_user</span>
                  <h2 className="font-headline text-2xl font-black text-on-surface">방어 시연</h2>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <AgentStatusBadge label="Blue Agent" status={defenseState.status} color="tertiary" />
                  <AgentStatusBadge label="Judge Agent" status={defenseJudge.status} color="primary" />
                </div>
              </div>

              <div className="flex-1 space-y-4 overflow-auto p-6">
                {defenseMessages.length === 0 ? (
                  <div className="flex h-full min-h-[360px] items-center justify-center rounded-2xl border border-dashed border-white/10 bg-white/[0.03] text-sm text-on-surface-variant">
                    공격 응답 생성 후 방어 실행
                  </div>
                ) : (
                  defenseMessages.map((message, idx) => <ChatBubble key={`defense-${message.role}-${idx}`} message={message} />)
                )}
                {defenseState.status === "loading" && (
                  <div className="mr-auto rounded-2xl border border-primary/25 bg-primary/10 p-4 text-sm font-black text-primary">
                    Blue Agent 실행 중
                  </div>
                )}
              </div>

              <div className="border-t border-white/10 p-5">
                <div className="flex gap-3">
                  <textarea
                    value={defenseInput}
                    onChange={(event) => setDefenseInput(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" && !event.shiftKey) {
                        event.preventDefault();
                        void sendDefense();
                      }
                    }}
                    placeholder="같은 공격 프롬프트를 붙여넣으세요. (Enter 전송 / Shift+Enter 줄바꿈)"
                    className="min-h-[92px] flex-1 resize-none rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm leading-6 text-on-surface outline-none transition-all placeholder:text-on-surface-variant/45 focus:border-tertiary/40"
                  />
                  <button
                    type="button"
                    onClick={sendDefense}
                    disabled={(!defenseInput.trim() && !attackMessages.some((message) => message.role === "user")) || !lastAttackResponse || defenseState.status === "loading"}
                    className="w-28 shrink-0 rounded-2xl bg-tertiary px-4 py-3 text-sm font-black text-[#06201C] transition-all hover:-translate-y-0.5 disabled:opacity-45"
                  >
                    전송
                  </button>
                </div>
              </div>
            </div>

            <div className="glass-panel rounded-[2rem] p-6">
              <h2 className="font-headline text-xl font-black text-on-surface">방어 판정 요약</h2>
              {defenseJudge.status === "idle" ? (
                <div className="mt-4 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-on-surface-variant">
                  방어 판정 대기
                </div>
              ) : defenseJudge.status === "loading" ? (
                <div className="mt-4 rounded-2xl border border-primary/25 bg-primary/10 p-4 text-sm font-black text-primary">
                  Judge 실행 중
                </div>
              ) : defenseJudge.status === "error" ? (
                <div className="mt-4 rounded-2xl border border-error/30 bg-error/10 p-4 text-sm text-error">
                  {defenseJudge.detail}
                </div>
              ) : (
                <div className="mt-4 space-y-3">
                  {judgeFacts(defenseJudge.result).map(([label, value]) => (
                    <div key={label} className="rounded-xl border border-tertiary/20 bg-tertiary/10 p-3">
                      <p className="text-[10px] font-black uppercase tracking-[0.16em] text-tertiary">{label}</p>
                      <p className="mt-1 break-words font-mono text-xs leading-5 text-on-surface">{String(value)}</p>
                    </div>
                  ))}
                  {defenseState.rationale && (
                    <div className="rounded-xl border border-white/10 bg-white/5 p-3">
                      <p className="text-[10px] font-black uppercase tracking-[0.16em] text-on-surface-variant/60">근거</p>
                      <p className="mt-1 break-words text-xs leading-5 text-on-surface-variant">{defenseState.rationale}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>
        )}

        {activeView === "judge" && (
          <section className="glass-panel rounded-[2rem] border border-white/10 p-0">
            <div className="border-b border-white/10 p-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex min-w-0 items-center gap-4">
                  <span className={`flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl border border-white/15 bg-white/5 ${verdictClass(attackJudge.result?.judgment)}`}>
                    <span className="material-symbols-outlined">{attackJudge.result?.judgment === "vulnerable" ? "gpp_bad" : "fact_check"}</span>
                  </span>
                  <div className="min-w-0">
                    <p className={`text-xs font-black uppercase tracking-[0.18em] ${verdictClass(attackJudge.result?.judgment)}`}>
                      {attackJudge.status === "done" ? "Judge Result" : "Judge 대기"}
                    </p>
                    {(() => {
                      const category = normalizeCategory(attackJudge.result?.category);
                      return (
                        <h2 className={`mt-1 break-words font-headline text-3xl font-black ${CATEGORY_COLORS[category] ?? "text-on-surface"}`}>
                          {category ? `${category} · ${CATEGORY_LABELS[category]}` : "카테고리 판정 대기"}
                        </h2>
                      );
                    })()}
                  </div>
                </div>
                <Link
                  href={`/report/${demoReportSessionId}`}
                  onClick={saveDemoReportSnapshot}
                  className="inline-flex shrink-0 items-center justify-center gap-2 rounded-2xl bg-primary px-5 py-3 text-sm font-black text-on-primary transition-all hover:-translate-y-0.5"
                >
                  <span className="material-symbols-outlined text-lg">article</span>
                  전체 리포트
                </Link>
              </div>
            </div>

            <div className="p-6">
              {attackJudge.status !== "done" && (
                <div className="mb-5 rounded-2xl border border-dashed border-white/10 bg-white/[0.03] p-6 text-sm text-on-surface-variant">
                  공격 응답과 Judge 결과가 있어야 판정 리포트가 표시됩니다.
                </div>
              )}
              {attackJudge.result && (
                <div className="mb-5 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                  {judgeFacts(attackJudge.result).map(([key, value]) => (
                    <div key={key} className="min-w-0 rounded-2xl border border-white/10 bg-white/5 p-3">
                      <p className="text-[9px] font-black uppercase tracking-[0.14em] text-on-surface-variant/50">{key}</p>
                      <p className="mt-1 break-words font-mono text-xs font-black leading-5 text-on-surface">{String(value)}</p>
                    </div>
                  ))}
                </div>
              )}

              <div className="grid gap-4 xl:grid-cols-2">
                <div>
                  <div className="mb-3 flex items-center gap-3">
                    <span className="material-symbols-outlined text-error">account_tree</span>
                    <p className="font-headline text-lg font-black text-on-surface">공격 판정 그래프</p>
                  </div>
                  <LangGraphFlow judge={attackJudge.result} />
                </div>
                <div>
                  <div className="mb-3 flex items-center gap-3">
                    <span className="material-symbols-outlined text-tertiary">account_tree</span>
                    <p className="font-headline text-lg font-black text-on-surface">방어 판정 그래프</p>
                  </div>
                  <LangGraphFlow judge={defenseJudge.result} />
                </div>
              </div>

              <div className="mt-5 grid gap-4 xl:grid-cols-2">
                <div className="rounded-2xl border border-error/25 bg-error/10 p-5">
                  <div className="mb-4 flex items-center gap-2">
                    <span className="material-symbols-outlined text-error">warning</span>
                    <p className="font-headline text-lg font-black text-error">공격 응답 판정</p>
                  </div>
                  <div className="mb-4 grid gap-2 md:grid-cols-3">
                    {[
                      ["판정", attackJudge.result?.judgment || "-"],
                      ["심각도", attackJudge.result?.severity || "-"],
                      ["근거", attackJudge.result?.failure_mode || "-"],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-xl border border-error/15 bg-black/25 p-3">
                        <p className="text-[10px] font-black uppercase tracking-[0.12em] text-error/80">{label}</p>
                        <p className="mt-1 break-words text-sm font-black text-on-surface">{value}</p>
                      </div>
                    ))}
                  </div>
                  <pre className="max-h-[270px] overflow-auto whitespace-pre-wrap break-words rounded-xl border border-error/20 bg-black/25 p-4 font-mono text-xs leading-6 text-on-surface">
                    {shownResponseDisplay ? highlightEvidence(shownResponseDisplay) : "공격 응답 없음"}
                  </pre>
                  <div className="mt-4 rounded-xl border border-error/20 bg-black/30 p-4">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-error text-base">psychology_alt</span>
                        <p className="text-xs font-black uppercase tracking-[0.14em] text-error/85">판정 근거 · Consensus</p>
                      </div>
                      {isTranslatingDetail && (
                        <span className="flex items-center gap-1.5 text-[10px] text-primary">
                          <span className="agent-pulse h-1.5 w-1.5 rounded-full bg-primary" />
                          번역 중
                        </span>
                      )}
                    </div>
                    <p className="break-words text-xs leading-6 text-on-surface-variant">
                      {translatedDetail
                        || (attackJudge.result?.reason_sources?.consensus_reason as string | undefined)
                        || attackJudge.result?.detail
                        || attackJudge.detail
                        || "판정 근거 없음"}
                    </p>
                  </div>
                </div>

                <div className="rounded-2xl border border-tertiary/25 bg-tertiary/10 p-5">
                  <div className="mb-4 flex items-center gap-2">
                    <span className="material-symbols-outlined text-tertiary">shield</span>
                    <p className="font-headline text-lg font-black text-tertiary">방어 응답 판정</p>
                  </div>
                  <div className="mb-4 grid gap-2 md:grid-cols-3">
                    {[
                      ["판정", defenseJudge.result?.judgment || "-"],
                      ["점수", defenseJudge.result?.score ?? defenseJudge.result?.confidence ?? "-"],
                      ["근거", defenseJudge.result?.failure_mode || "-"],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-xl border border-tertiary/20 bg-black/20 p-3">
                        <p className="text-[10px] font-black uppercase tracking-[0.12em] text-tertiary">{label}</p>
                        <p className="mt-1 break-words text-sm font-black text-on-surface">{String(value)}</p>
                      </div>
                    ))}
                  </div>
                  <pre className="max-h-[270px] overflow-auto whitespace-pre-wrap break-words rounded-xl border border-tertiary/20 bg-black/20 p-4 font-mono text-xs leading-6 text-on-surface">
                    {lastDefenseResponseDisplay || "방어 응답 없음"}
                  </pre>
                  <div className="mt-4 rounded-xl border border-tertiary/20 bg-black/25 p-4">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-tertiary text-base">psychology_alt</span>
                        <p className="text-xs font-black uppercase tracking-[0.14em] text-tertiary/85">판정 근거 · Consensus</p>
                      </div>
                      {isTranslatingDefenseDetail && (
                        <span className="flex items-center gap-1.5 text-[10px] text-primary">
                          <span className="agent-pulse h-1.5 w-1.5 rounded-full bg-primary" />
                          번역 중
                        </span>
                      )}
                    </div>
                    <p className="break-words text-xs leading-6 text-on-surface-variant">
                      {translatedDefenseDetail
                        || (defenseJudge.result?.reason_sources?.consensus_reason as string | undefined)
                        || defenseJudge.result?.detail
                        || defenseJudge.detail
                        || "판정 근거 없음"}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}
      </div>

      <style jsx global>{`
        @keyframes demoFlowDash {
          from { background-position: 0 0; }
          to { background-position: 64px 0; }
        }

        @keyframes demoNodePulse {
          0%, 100% { box-shadow: 0 0 18px rgba(14, 165, 165, 0.22); }
          50% { box-shadow: 0 0 34px rgba(45, 212, 212, 0.46); }
        }

        @keyframes demoLinkArrowBlink {
          0%, 100% { opacity: 0.42; transform: translateX(0); }
          50% { opacity: 1; transform: translateX(4px); }
        }

        .demo-step-connector {
          position: relative;
          z-index: 15;
          display: inline-flex;
          min-width: 2.75rem;
          flex: 1 1 3.75rem;
          height: 22px;
          align-items: center;
        }

        .demo-step-connector::before {
          content: "";
          position: absolute;
          left: 0.35rem;
          right: 0.55rem;
          top: 50%;
          height: 5px;
          transform: translateY(-50%);
          border-radius: 999px;
          background:
            repeating-linear-gradient(
              90deg,
              rgba(45, 212, 212, 0.38) 0,
              rgba(45, 212, 212, 0.38) 26px,
              rgba(45, 212, 212, 0.12) 26px,
              rgba(45, 212, 212, 0.12) 52px
            );
          box-shadow: 0 0 22px rgba(45, 212, 212, 0.34);
          animation: demoFlowDash 2.4s linear infinite;
        }

        .demo-step-connector::after {
          content: ">";
          position: absolute;
          right: 0;
          top: 50%;
          transform: translateY(-54%);
          color: #0ea5a5;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
          font-size: 2.1rem;
          font-weight: 900;
          line-height: 1;
          text-shadow: 0 0 10px rgba(14, 165, 165, 0.62);
        }

        .demo-active-node {
          animation: demoNodePulse 1.35s ease-in-out infinite;
        }

        .demo-link-arrow {
          animation: demoLinkArrowBlink 1.1s ease-in-out infinite;
        }

        .judge-graph-node {
          min-height: 62px;
          border-width: 1px;
          border-radius: 0.75rem;
          padding: 0.65rem 0.8rem;
          text-align: center;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          word-break: keep-all;
          overflow-wrap: anywhere;
        }

        .graph-svg-line {
          fill: none;
          stroke: url(#line-demo);
          stroke-width: 3;
          stroke-linecap: round;
          stroke-linejoin: round;
          stroke-dasharray: 14 10;
          animation: graphStrokeMove 1.1s linear infinite;
        }

        .graph-center-line {
          stroke: #2dd4d4;
          stroke-dasharray: 14 10;
          animation: graphStrokeMove 1.1s linear infinite;
          stroke-width: 3.2;
          opacity: 0.95;
        }

        .graph-svg-line.line-b {
          animation-delay: 0.08s;
        }

        .graph-svg-line.line-c {
          animation-delay: 0.16s;
        }

        .graph-svg-line.line-d {
          animation-delay: 0.28s;
        }

        .graph-svg-line.line-e {
          animation-delay: 0.36s;
        }

        .graph-svg-line.line-f {
          animation-delay: 0.44s;
        }

        .graph-svg-line.line-g {
          animation-delay: 0.62s;
        }

        @keyframes graphStrokeMove {
          from { stroke-dashoffset: 90; }
          to { stroke-dashoffset: 0; }
        }

        @keyframes agentPulse {
          0%, 100% { opacity: 0.35; transform: scale(0.8); }
          50% { opacity: 1; transform: scale(1.25); }
        }

        .agent-pulse {
          animation: agentPulse 0.85s ease-in-out infinite;
        }
      `}</style>
    </DashboardLayout>
  );
}
