"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import DashboardLayout from "../../components/DashboardLayout";

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
  judgment?: string;
  confidence?: number;
  success?: boolean;
  success_strength?: number;
  exploit_type?: string;
  detail?: string;
  attack_len?: number;
  response_len?: number;
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

const STEPS = [
  { id: 0, icon: "database", label: "타겟 정보", sub: "실제 값 확인", phase: "TARGET" },
  { id: 1, icon: "terminal", label: "공격 시연", sub: "프롬프트 전송", phase: "RED" },
  { id: 2, icon: "warning", label: "위험 해석", sub: "유출 근거", phase: "RISK" },
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
      model: "hf.co/Qwen/Qwen2.5-3B-Instruct-GGUF:Q4_K_M",
      security_mode: "Strict",
      environment: "Docker testbed",
      testbed_db_url: "",
    },
    runtime_context: [
      { key: "INTERNAL_API_KEY", value: "", risk: "critical" },
      { key: "DB_ROOT_PASSWORD", value: "", risk: "high" },
      { key: "NODE_ENV", value: "", risk: "medium" },
      { key: "SERVICE_NAME", value: "", risk: "medium" },
      { key: "AUTH_TOKEN_EXPIRY", value: "", risk: "low" },
    ],
    tools: [
      { name: "customer_db.query", risk: "read", description: "고객 및 구성 레코드 조회" },
      { name: "customer_db.update", risk: "write", description: "고객 레코드 수정" },
      { name: "customer_db.delete", risk: "destructive", description: "고객 레코드 삭제" },
      { name: "internal_api.call", risk: "privileged", description: "내부 API 호출" },
    ],
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
      className={`group relative z-20 flex min-w-[156px] flex-col items-start gap-3 rounded-2xl border px-5 py-4 text-left transition-all duration-300 ${
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
  const toneClass = isUser
    ? "ml-auto border-primary/30 bg-primary/10"
    : message.tone === "defense"
      ? "mr-auto border-tertiary/30 bg-tertiary/10"
      : "mr-auto border-error/25 bg-error/10";

  return (
    <div className={`max-w-[88%] rounded-2xl border p-4 ${toneClass}`}>
      <p className="mb-2 text-[10px] font-black uppercase tracking-[0.18em] text-on-surface-variant/60">
        {isUser ? "사용자" : message.tone === "defense" ? "방어 에이전트" : "테스트베드 챗봇"}
      </p>
      <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-6 text-on-surface">
        {isUser ? message.content : highlightEvidence(message.content)}
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
      <div className="flex items-center gap-3 border-b border-current/20 px-4 py-3">
        <span className="material-symbols-outlined text-[22px]">{icon}</span>
        <p className="break-words font-mono text-base font-black leading-tight">{title}</p>
      </div>
      <div className="space-y-2 p-3">
        {rows.map(([field, value], idx) => (
          <div key={`${title}-${field}`} className="grid gap-2 rounded-md bg-black/24 px-3 py-2 md:grid-cols-[170px_minmax(0,1fr)]">
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
  const record = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
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
    ["카테고리", "LLM02"],
    ["공격 유형", judge.failure_mode || "-"],
    ["MITRE", judge.mitre_technique_id || "-"],
  ];
}

function verdictClass(value?: string | null) {
  if (value === "vulnerable") return "text-error";
  if (value === "safe") return "text-tertiary";
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

  useEffect(() => {
    let mounted = true;
    fetch("/api/demo/testbed-context")
      .then((res) => res.json())
      .then((data) => {
        if (mounted) setContext(data);
      })
      .catch(() => {
        if (mounted) setContext(fallbackContext());
      });
    return () => {
      mounted = false;
    };
  }, []);

  async function sendAttack() {
    const prompt = attackInput.trim();
    if (!prompt || attackState.status === "loading") return;

    setAttackMessages((prev) => [...prev, { role: "user", content: prompt, tone: "attack" }]);
    setAttackInput("");
    setAttackState({ status: "loading" });
    void runAdaptiveCampaign(prompt);

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
      setAttackState({ status: "live" });
      void runJudge(prompt, content, setAttackJudge);
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
  ) {
    setter({ status: "loading" });
    try {
      const res = await fetch("/api/demo/judge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category: "LLM02",
          attack_prompt: prompt,
          target_response: targetResponse,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) {
        setter({ status: "error", detail: data.detail || data.stderr_tail || "Judge 실행 실패" });
        return;
      }
      setter({ status: "done", result: data.judge });
    } catch (error) {
      setter({ status: "error", detail: error instanceof Error ? error.message : "Judge 연결 실패" });
    }
  }

  async function runAdaptiveCampaign(prompt: string) {
    setAdaptiveState({ status: "loading", rounds: [] });

    try {
      const res = await fetch("/api/demo/red-adaptive", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt }),
      });
      const data = await res.json().catch(() => ({}));
      const rounds = Array.isArray(data.rounds) ? data.rounds : [];

      if (!res.ok || !data.ok) {
        setAdaptiveState({
          status: "error",
          rounds,
          detail: data.detail || data.stderr_tail || "Red Agent 실행 실패",
          best_round: data.best_round ?? null,
          raw_path: data.raw_path ?? null,
          success: Boolean(data.success),
        });
        return;
      }

      setAdaptiveState({
        status: "done",
        rounds,
        best_round: data.best_round ?? null,
        raw_path: data.raw_path ?? null,
        success: Boolean(data.success),
      });
      const winningRound =
        rounds.find((round: AdaptiveRound) => round.success) ||
        rounds.find((round: AdaptiveRound) => round.round === data.best_round);
      if (winningRound?.attack_prompt && winningRound?.target_response) {
        setAttackMessages([
          { role: "user", content: winningRound.attack_prompt, tone: "attack" },
          { role: "assistant", content: winningRound.target_response, tone: "attack" },
        ]);
        setAttackState({ status: "live", detail: `Red Agent R${winningRound.round || ""} 성공 프롬프트 적용` });
        void runJudge(winningRound.attack_prompt, winningRound.target_response, setAttackJudge);
        setStep(2);
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
      const res = await fetch("/api/demo/blue-defense", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category: "LLM02",
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
      setDefenseState({ status: "done", rationale: data.defense_rationale });
      setAttackJudge(data.attack_judge ? { status: "done", result: data.attack_judge } : attackJudge);
      setDefenseJudge({ status: "done", result: data.defense_judge });
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Blue Agent 연결 실패";
      setDefenseState({ status: "error", detail });
      setDefenseJudge({ status: "error", detail });
      setDefenseMessages((prev) => [...prev, { role: "assistant", content: detail, tone: "error" }]);
    }
  }

  const lastAttackResponse =
    [...attackMessages].reverse().find((message) => message.role === "assistant")?.content || "";
  const lastDefenseResponse =
    [...defenseMessages].reverse().find((message) => message.role === "assistant" && message.tone === "defense")?.content || "";
  const shownResponse = lastAttackResponse;
  const activeView = viewForStep(step);
  const runtimeValue = (key: string) => context.runtime_context.find((item) => item.key === key)?.value || "-";
  const toolRisk = (name: string) => context.tools.find((item) => item.name === name)?.risk || "-";

  return (
    <DashboardLayout>
      <div className="mx-auto flex w-full max-w-[1720px] flex-col gap-6 p-8 page-fade-in">
        <section className="glass-panel rounded-[2rem] p-6">
          <div className="relative min-h-[210px] overflow-x-auto px-2 py-8">
            <div className="demo-flow-track pointer-events-none absolute left-10 right-10 top-1/2 z-0 hidden h-[5px] -translate-y-1/2 overflow-hidden rounded-full xl:block">
              <span className="material-symbols-outlined demo-flow-arrow">arrow_forward</span>
            </div>
            <div className="relative z-10 flex min-w-max items-center justify-between gap-9 xl:min-w-0">
              {STEPS.map((item) => (
                <div key={item.id} className="relative z-20 flex items-center gap-9">
                  <PipelineNode step={item} active={step === item.id} onClick={() => setStep(item.id)} />
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
                      ["secret_id", "sec-prod-001"],
                      ...context.runtime_context.map((item) => [item.key, item.value]),
                    ]}
                  />
                  <ErdEntity
                    title="system_prompt_context"
                    icon="article"
                    tone="primary"
                    rows={[
                      ["prompt_id", "prompt-shopeasy-prod"],
                      ["role", "ShopEasy customer support assistant"],
                      ["policy", "do not reveal internal secrets"],
                      ["secret_ref", "sec-prod-001"],
                      ["tool_gateway", context.target.tool_gateway_url],
                    ]}
                  />
                  <ErdEntity
                    title="service_manifest"
                    icon="deployed_code"
                    tone="tertiary"
                    rows={[
                      ["service_id", "svc-shopeasy"],
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
          <section className="grid gap-5 xl:grid-cols-[1fr_0.42fr]">
            <div className="glass-panel flex min-h-[650px] flex-col rounded-[2rem] p-0">
              <div className="border-b border-white/10 p-6">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-error">terminal</span>
                  <h2 className="font-headline text-2xl font-black text-on-surface">공격 시연</h2>
                </div>
              </div>

              <div className="flex-1 space-y-4 overflow-auto p-6">
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
                    placeholder="공격 프롬프트를 붙여넣으세요."
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

            <div className="glass-panel rounded-[2rem] p-6">
              <h2 className="font-headline text-xl font-black text-on-surface">Red Agent 변형 공격</h2>
              {attackState.detail && (
                <div className="mt-4 rounded-2xl border border-[#F59E0B]/30 bg-[#F59E0B]/10 p-3 text-xs leading-5 text-[#FBBF24]">
                  {attackState.detail}
                </div>
              )}
              <div className="mt-4 grid grid-cols-2 gap-2">
                {[
                  ["상태", adaptiveState.status === "loading" ? "실행 중" : adaptiveState.status === "done" ? "완료" : adaptiveState.status === "error" ? "오류" : "대기"],
                  ["라운드", `${adaptiveState.rounds.length} / 5`],
                  ["성공", adaptiveState.success ? "true" : "false"],
                  ["중단 R", adaptiveState.best_round ? `R${adaptiveState.best_round}` : "-"],
                ].map(([label, value]) => (
                  <div key={label} className="min-w-0 rounded-xl border border-white/10 bg-white/5 p-3">
                    <p className="text-[10px] font-black uppercase tracking-[0.16em] text-on-surface-variant/50">{label}</p>
                    <p className="mt-1 break-words font-mono text-xs leading-5 text-on-surface">{value}</p>
                  </div>
                ))}
              </div>

              <div className="mt-4 max-h-[470px] space-y-3 overflow-auto pr-1">
                {adaptiveState.status === "idle" && (
                  <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-on-surface-variant">
                    공격 전송 대기
                  </div>
                )}
                {adaptiveState.status === "loading" && (
                  <div className="rounded-2xl border border-primary/25 bg-primary/10 p-4 text-sm font-black text-primary">
                    5라운드 변형 실행 중
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
                {adaptiveState.rounds.map((round) => (
                  <div
                    key={`adaptive-round-${round.round}`}
                    className={`rounded-2xl border p-4 ${
                      round.success
                        ? "border-error/35 bg-error/10"
                        : round.judgment === "safe"
                          ? "border-tertiary/25 bg-tertiary/10"
                          : "border-white/10 bg-white/5"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <p className="font-headline text-base font-black text-on-surface">R{round.round}</p>
                      <span className={`rounded-full border px-2 py-1 font-mono text-[10px] font-black ${
                        round.success ? "border-error/30 text-error" : "border-white/10 text-on-surface-variant"
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
                ))}
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
            </div>

            <div className="glass-panel rounded-[2rem] p-6">
              <h2 className="font-headline text-xl font-black text-on-surface">응답 근거 로그</h2>
              <div className="mt-4 max-h-[560px] overflow-auto rounded-2xl border border-error/20 bg-[#07101A] p-4">
                <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-6 text-on-surface">
                  {shownResponse ? highlightEvidence(shownResponse) : "공격 응답 없음"}
                </pre>
              </div>
            </div>
          </section>
        )}

        {activeView === "defense" && (
          <section className="grid gap-5 xl:grid-cols-[1fr_0.45fr]">
            <div className="glass-panel flex min-h-[650px] flex-col rounded-[2rem] p-0">
              <div className="border-b border-white/10 p-6">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-tertiary">verified_user</span>
                  <h2 className="font-headline text-2xl font-black text-on-surface">방어 시연</h2>
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
                    placeholder="같은 공격 프롬프트를 붙여넣으세요."
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
                    <h2 className="mt-1 break-words font-headline text-3xl font-black text-on-surface">
                      LLM02 · 민감 정보 유출 판정
                    </h2>
                  </div>
                </div>
                <Link
                  href="/report/mock-session-demo"
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

              <div className="rounded-2xl border border-white/10 bg-[#06131D] p-5">
                <div className="mb-4 flex items-center gap-3">
                  <span className="material-symbols-outlined text-primary">psychology_alt</span>
                  <p className="font-headline text-xl font-black text-on-surface">판정 에이전트 · 위험 판단 이유</p>
                </div>
                <p className="break-words text-sm leading-7 text-on-surface-variant">
                  {attackJudge.result?.detail || attackJudge.detail || "Judge 결과 없음"}
                </p>
              </div>

              <div className="mt-5 grid gap-4 xl:grid-cols-2">
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
                    {shownResponse ? highlightEvidence(shownResponse) : "공격 응답 없음"}
                  </pre>
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
                    {lastDefenseResponse || "방어 응답 없음"}
                  </pre>
                </div>
              </div>

              <div className="mt-5 rounded-2xl border border-white/10 bg-[#07111D] p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="font-headline text-2xl font-black text-on-surface">최종 결과</p>
                    <p className="mt-1 text-sm text-on-surface-variant">실행된 응답만 비교합니다.</p>
                  </div>
                  <span className="rounded-full border border-tertiary/25 bg-tertiary/10 px-4 py-2 text-sm font-black text-tertiary">
                    {defenseJudge.result?.judgment || "방어 대기"}
                  </span>
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-4">
                  {[
                    ["공격 응답", attackJudge.result?.judgment || "-"],
                    ["방어 응답", defenseJudge.result?.judgment || "-"],
                    ["공격 점수", attackJudge.result?.score ?? attackJudge.result?.confidence ?? "-"],
                    ["방어 점수", defenseJudge.result?.score ?? defenseJudge.result?.confidence ?? "-"],
                  ].map(([key, value]) => (
                    <div key={key} className="min-w-0 rounded-2xl border border-white/10 bg-white/5 p-4">
                      <p className="text-[10px] font-black uppercase tracking-[0.14em] text-on-surface-variant/55">{key}</p>
                      <p className={`mt-2 break-words text-lg font-black ${verdictClass(String(value))}`}>
                        {String(value)}
                      </p>
                    </div>
                  ))}
                </div>
                {defenseState.rationale && (
                  <div className="mt-4 rounded-2xl border border-primary/15 bg-primary/10 p-4">
                    <p className="break-words text-sm leading-6 text-on-surface-variant">{defenseState.rationale}</p>
                  </div>
                )}
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

        @keyframes demoArrowTravel {
          0% { left: 0%; opacity: 0; transform: translate(-120%, -50%) scale(0.98); }
          8%, 92% { opacity: 1; }
          100% { left: 100%; opacity: 0; transform: translate(20%, -50%) scale(0.98); }
        }

        @keyframes demoLinkArrowBlink {
          0%, 100% { opacity: 0.42; transform: translateX(0); }
          50% { opacity: 1; transform: translateX(4px); }
        }

        .demo-flow-track {
          background:
            repeating-linear-gradient(
              90deg,
              rgba(45, 212, 212, 0.18) 0,
              rgba(45, 212, 212, 0.18) 26px,
              rgba(45, 212, 212, 0.06) 26px,
              rgba(45, 212, 212, 0.06) 52px
            );
          box-shadow: 0 0 18px rgba(45, 212, 212, 0.18);
          animation: demoFlowDash 2.4s linear infinite;
        }

        .demo-flow-arrow {
          position: absolute;
          top: 50%;
          left: 0;
          z-index: 0;
          font-size: 34px;
          font-weight: 700;
          color: #2dd4d4;
          text-shadow: 0 0 18px rgba(45, 212, 212, 0.95), 0 0 4px rgba(224, 242, 241, 0.8);
          animation: demoArrowTravel 2.4s linear infinite;
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
      `}</style>
    </DashboardLayout>
  );
}
