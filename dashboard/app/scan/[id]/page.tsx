"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import DashboardLayout from "../../../components/DashboardLayout";
import PipelineFlowViz from "../../../components/PipelineFlowViz";
import { getScanStatus, getScanResults, cancelScan, ScanResult } from "../../../lib/api";

const PHASE_LABELS: Record<number, string> = {
  1: "Phase 1 — 정적 스캐너",
  2: "Phase 2 — Red Agent 공격",
  3: "Phase 3 — Blue Agent 방어",
  4: "Phase 4 — 검증",
};

const SEVERITY_CONFIG: Record<string, { cls: string; dot: string; label: string }> = {
  critical: { cls: "text-error border-error/30 bg-error/10", dot: "bg-error", label: "긴급" },
  high:     { cls: "text-primary border-primary/30 bg-primary/10", dot: "bg-primary", label: "높음" },
  medium:   { cls: "text-on-surface-variant border-white/10 bg-white/5", dot: "bg-on-surface-variant", label: "중간" },
  low:      { cls: "text-tertiary border-tertiary/30 bg-tertiary/10", dot: "bg-tertiary", label: "낮음" },
};

const JUDGMENT_CONFIG: Record<string, { label: string; cls: string; icon: string }> = {
  vulnerable: { label: "취약", cls: "text-error bg-error/10 border-error/30", icon: "gpp_bad" },
  safe:       { label: "안전", cls: "text-tertiary bg-tertiary/10 border-tertiary/30", icon: "verified_user" },
  ambiguous:  { label: "모호", cls: "text-on-surface-variant bg-white/5 border-white/10", icon: "help" },
};

interface LogEntry {
  time: string;
  level: string;
  levelCls: string;
  msg: string;
  alert?: boolean;
  count?: number;
}

type ScanStatus = Awaited<ReturnType<typeof getScanStatus>>;

const PHASE_ACCENTS: Record<number, { icon: string; cls: string; line: string }> = {
  1: { icon: "radar", cls: "text-primary border-primary/25 bg-primary/10", line: "from-primary/70" },
  2: { icon: "neurology", cls: "text-error border-error/25 bg-error/10", line: "from-error/70" },
  3: { icon: "shield", cls: "text-tertiary border-tertiary/25 bg-tertiary/10", line: "from-tertiary/70" },
  4: { icon: "fact_check", cls: "text-blue-300 border-blue-300/25 bg-blue-300/10", line: "from-blue-300/70" },
};

const VERIFY_CONFIG: Record<string, { label: string; cls: string }> = {
  blocked: { label: "차단됨", cls: "text-tertiary border-tertiary/20 bg-tertiary/5" },
  safe: { label: "차단됨", cls: "text-tertiary border-tertiary/20 bg-tertiary/5" },
  mitigated: { label: "완화됨", cls: "text-tertiary border-tertiary/20 bg-tertiary/5" },
  bypassed: { label: "우회됨", cls: "text-error border-error/20 bg-error/5" },
  unsafe: { label: "우회됨", cls: "text-error border-error/20 bg-error/5" },
};

function compactText(value?: string | null) {
  return String(value || "").trim();
}

function looksLikeDefensePath(value: string) {
  return /^data\/phase3_defenses\/.+\.json$/i.test(value.trim());
}

function phaseTitle(result: ScanResult) {
  if (result.phase === 1) return "시드 공격 판정";
  if (result.phase === 2) return `Red Agent R${result.round ?? "?"}`;
  if (result.phase === 3) return "Blue Agent 방어 생성";
  if (result.phase === 4) return "Phase 4 방어 검증";
  return `Phase ${result.phase}`;
}

function phaseSubtitle(result: ScanResult) {
  if (result.phase === 1) return "DB 시드 공격 -> 타겟 응답 -> Judge 판정";
  if (result.phase === 2) return "Safe 시드 기반 적응형 공격 -> 타겟 응답 -> Judge 재판정";
  if (result.phase === 3) return "취약 결과 기반 방어 응답 생성";
  if (result.phase === 4) return "Blue 방어 적용 후 우회 여부 재검증";
  return "파이프라인 결과";
}

function detailText(result: ScanResult) {
  const raw = compactText(result.summary || result.detail);
  if (!raw) return `${result.category || "LLM"} 카테고리 판정 상세가 아직 비어 있습니다.`;
  if (result.phase === 4 && looksLikeDefensePath(raw)) {
    const verdict = VERIFY_CONFIG[String(result.verify_result || "").toLowerCase()]?.label || "검증 완료";
    return `${verdict}. 방어 결과 파일은 메타 정보로 분리 표시됩니다.`;
  }
  return raw;
}

function probabilityText(result: ScanResult) {
  if (typeof result.p_vulnerable === "number") {
    return `${Math.round(result.p_vulnerable * 100)}% risk`;
  }
  if (typeof result.judgment_confidence === "number") {
    return `${Math.round(result.judgment_confidence * 100)}% conf`;
  }
  return "n/a";
}

function MetaPill({ label, value }: { label: string; value?: string | number | null }) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <span className="inline-flex min-w-0 items-center gap-1 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 font-mono text-[10px] text-on-surface-variant">
      <span className="shrink-0 text-on-surface-variant/45">{label}</span>
      <span className="truncate text-on-surface/75">{value}</span>
    </span>
  );
}

function TextPanel({
  icon,
  label,
  value,
  tone = "default",
  mono = false,
}: {
  icon: string;
  label: string;
  value: string;
  tone?: "default" | "primary" | "error" | "tertiary";
  mono?: boolean;
}) {
  const tones = {
    default: "bg-white/5 border-white/10 text-on-surface-variant",
    primary: "bg-primary/10 border-primary/20 text-primary",
    error: "bg-error/10 border-error/20 text-error",
    tertiary: "bg-tertiary/10 border-tertiary/20 text-tertiary",
  };
  return (
    <div className="flex gap-3" style={{ animation: "slideInLeft 0.35s ease-out" }}>
      <div className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border ${tones[tone]}`}>
        <span className="material-symbols-outlined text-[15px]" style={{ fontVariationSettings: "'FILL' 1" }}>{icon}</span>
      </div>
      <div className="min-w-0 flex-1">
        <p className="mb-1 text-[10px] font-black uppercase tracking-[0.18em] text-on-surface-variant/55">{label}</p>
        <div className="max-h-36 overflow-y-auto overflow-x-auto rounded-xl border border-white/5 bg-black/15 px-3 py-2">
          <p className={`${mono ? "font-mono" : ""} whitespace-pre-wrap break-words text-xs leading-5 text-on-surface/80`}>
            {value || "—"}
          </p>
        </div>
      </div>
    </div>
  );
}

// 결과 카드 — 시드/라운드/판정/방어 검증 흐름을 한눈에 표시
function ResultCard({ result, index }: { result: ScanResult; index: number }) {
  const [step, setStep] = useState(0); // 0=공격 1=응답 2=판정 3=방어
  const sev = SEVERITY_CONFIG[result.severity] ?? SEVERITY_CONFIG.medium;
  const jud = JUDGMENT_CONFIG[result.judgment] ?? JUDGMENT_CONFIG.ambiguous;
  const isVulnerable = result.judgment === "vulnerable";
  const phase = PHASE_ACCENTS[result.phase] ?? PHASE_ACCENTS[1];
  const verify = VERIFY_CONFIG[String(result.verify_result || "").toLowerCase()];
  const sourcePath = compactText(result.detail);
  const showSourcePath = result.phase === 4 && looksLikeDefensePath(sourcePath);
  const attackLabel = result.phase === 2 ? "Red Agent 공격 프롬프트" : result.phase === 4 ? "검증 공격 프롬프트" : "시드 공격 프롬프트";
  const responseLabel = result.phase === 4 ? "방어 적용 후 응답" : "테스트베드 챗봇 응답";

  useEffect(() => {
    // 카드 등장 후 각 스텝을 0.7초 간격으로 순차 공개
    const timers = [
      setTimeout(() => setStep(1), 700),
      setTimeout(() => setStep(2), 1400),
      setTimeout(() => setStep(3), 2100),
    ];
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div
      className={`glass-panel group relative flex-shrink-0 overflow-hidden rounded-2xl border shadow-lg transition-all duration-300 hover:-translate-y-0.5 hover:border-white/15 ${
        isVulnerable ? "border-error/15 shadow-error/10" : "border-white/5"
      }`}
      style={{ animation: "slideInUp 0.4s ease-out both" }}
    >
      <div className={`absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r ${phase.line} via-white/20 to-transparent`} />

      <div className={`border-b border-white/5 px-5 py-4 ${isVulnerable ? "bg-error/5" : "bg-white/[0.025]"}`}>
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="font-mono text-[10px] text-on-surface-variant/45">#{String(index + 1).padStart(3, "0")}</span>
              <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[10px] font-black ${phase.cls}`}>
                <span className="material-symbols-outlined text-[13px]" style={{ fontVariationSettings: "'FILL' 1" }}>{phase.icon}</span>
                {phaseTitle(result)}
              </span>
              <span className={`rounded-full border px-2.5 py-1 text-[10px] font-black ${sev.cls}`}>{sev.label}</span>
              <span className="rounded-lg bg-primary/5 px-2.5 py-1 font-mono text-[10px] text-primary/70">{result.category || "LLM"}</span>
            </div>
            <p className="font-headline text-base font-black text-on-surface">{phaseSubtitle(result)}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <MetaPill label="seed" value={result.seed_id || (result.phase === 4 ? result.seed_id : undefined)} />
              <MetaPill label="pattern" value={result.attack_pattern_id} />
              <MetaPill label="round" value={result.round ? `R${result.round}` : undefined} />
              <MetaPill label="sub" value={result.subcategory} />
              <MetaPill label="judge" value={probabilityText(result)} />
              {result.mitre_technique_id && <MetaPill label="mitre" value={result.mitre_technique_id} />}
            </div>
          </div>
          {step >= 2 && (
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <div className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[11px] font-black ${jud.cls}`}
                   style={{ animation: "fadeIn 0.3s ease-out" }}>
                <span className="material-symbols-outlined text-[14px]" style={{ fontVariationSettings: "'FILL' 1" }}>{jud.icon}</span>
                {jud.label}
              </div>
              {verify && (
                <span className={`rounded-full border px-3 py-1.5 text-[10px] font-black ${verify.cls}`}>
                  {verify.label}
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="space-y-3 p-5">
        <TextPanel icon="input" label={attackLabel} value={compactText(result.attack_prompt)} tone={result.phase === 2 ? "error" : "primary"} />

        {step >= 1 && (
          <TextPanel icon="forum" label={responseLabel} value={compactText(result.target_response)} tone="primary" mono />
        )}

        {step >= 2 && (
          <TextPanel icon="psychology" label="Judge 판정 근거" value={detailText(result).replace(/\. /g, ".\n")} tone={isVulnerable ? "error" : "tertiary"} />
        )}

        {step >= 3 && result.defense_code && (
          <TextPanel icon="shield" label="Blue Agent 방어 생성" value={compactText(result.defense_rationale || result.defense_code)} tone="tertiary" mono />
        )}

        {step >= 3 && result.defended_response && (
          <TextPanel icon="verified" label="방어 응답" value={compactText(result.defended_response)} tone="tertiary" mono />
        )}

        {step >= 3 && showSourcePath && (
          <div className="flex items-center justify-end gap-2 text-right font-mono text-[10px] text-on-surface-variant/35">
            <span className="material-symbols-outlined text-[13px]">folder_open</span>
            <span className="max-w-full truncate">{sourcePath}</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default function ScanDetailPage({ params }: { params: { id: string } }) {
  const router = useRouter();
  const sessionId = params.id;

  const [status, setStatus] = useState<{
    status: string;
    phase: number;
    total_tests: number;
    completed_tests: number;
    vulnerable_count: number;
    safe_count: number;
    ambiguous_count?: number;
    elapsed_seconds?: number;
  } | null>(null);

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [latestAttackPrompt, setLatestAttackPrompt] = useState("");

  // 순차 표시 상태
  const [displayedResults, setDisplayedResults] = useState<ScanResult[]>([]);
  const pendingQueue = useRef<ScanResult[]>([]);
  const seenIds = useRef<Set<number>>(new Set());
  const feedRef = useRef<HTMLDivElement>(null);

  const logRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<NodeJS.Timeout | null>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const elapsedRef = useRef(0);
  const [elapsed, setElapsed] = useState("00:00:00");

  function formatElapsed(secs: number): string {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    return [h, m, s].map((v) => String(v).padStart(2, "0")).join(":");
  }

  function addLog(level: string, msg: string, alert = false) {
    const now = new Date();
    const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;
    const levelCls: Record<string, string> = {
      INFO: "text-primary",
      OK: "text-tertiary",
      SCAN: "text-primary",
      CRITICAL: "text-error font-black tracking-wider",
      VULNERABLE: "text-error font-black tracking-wider",
      WARN: "text-[#F59E0B] font-bold",
      SAFE: "text-tertiary",
      ERROR: "text-error",
      DONE: "text-tertiary font-black",
    };
    setLogs((prev) => {
      // 직전 라인과 동일하면 새 라인 추가 대신 카운트만 증가 — 폴링 반복 출력 방지
      const last = prev[prev.length - 1];
      if (last && last.level === level && last.msg === msg) {
        const next = prev.slice();
        next[next.length - 1] = { ...last, time, count: (last.count ?? 1) + 1 };
        return next;
      }
      return [
        ...prev.slice(-100),
        { time, level, levelCls: levelCls[level] || "text-on-surface-variant", msg, alert, count: 1 },
      ];
    });
  }

  function stopLiveIntervals() {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }

  // 새 결과를 큐에 추가
  function enqueueNewResults(incoming: ScanResult[]) {
    const fresh = incoming.filter((r) => !seenIds.current.has(r.id));
    fresh.forEach((r) => seenIds.current.add(r.id));
    if (fresh.length > 0) {
      pendingQueue.current = [...pendingQueue.current, ...fresh];
    }
  }

  const fetchStatus = useCallback(async () => {
    try {
      const s = await getScanStatus(sessionId);
      setStatus(s);
      elapsedRef.current = s.elapsed_seconds || elapsedRef.current;
      setElapsed(formatElapsed(elapsedRef.current));

      if (s.status === "queued") {
        addLog("INFO", "스캔 작업이 백그라운드 큐에 등록되었습니다.");
      }

      if (s.status === "running") {
        const phaseLabel = PHASE_LABELS[s.phase] || `Phase ${s.phase}`;
        const ambiguous = s.ambiguous_count ?? 0;
        if (s.vulnerable_count > 0) {
          const suffix = ambiguous > 0 ? ` · 모호 ${ambiguous}개` : "";
          addLog("CRITICAL", `취약점 탐지됨: ${s.vulnerable_count}개${suffix} — ${phaseLabel} 진행 중...`, true);
        } else if (ambiguous > 0) {
          addLog("WARN", `모호 판정 ${ambiguous}개 — Judge 멀티에이전트 합의 보류 (${phaseLabel})`);
        } else {
          addLog("SCAN", `${phaseLabel} 실행 중... (${s.completed_tests}/${s.total_tests})`);
        }
        try {
          const partial = await getScanResults(sessionId);
          enqueueNewResults(partial);
          const last = partial.filter((x) => x.attack_prompt).at(-1)?.attack_prompt;
          if (last) setLatestAttackPrompt(last);
        } catch {
          addLog("ERROR", "실시간 결과를 아직 불러오지 못했습니다.");
        }
      }

      if (s.status === "completed") {
        addLog("DONE", "스캔 완료. 최종 결과를 불러오는 중...");
        let r: ScanResult[];
        try {
          r = await getScanResults(sessionId);
          if (r.length === 0 && (s.vulnerable_count > 0 || s.safe_count > 0 || (s.ambiguous_count ?? 0) > 0)) {
            await new Promise((res) => setTimeout(res, 1500));
            r = await getScanResults(sessionId);
          }
        } catch {
          r = [];
        }
        pendingQueue.current = [];
        seenIds.current = new Set(r.map((x) => x.id));
        setDisplayedResults(r.slice().reverse());
        stopLiveIntervals();
      } else if (s.status === "failed") {
        addLog("ERROR", s.error_message || "스캔 중 오류가 발생했습니다.");
        stopLiveIntervals();
      } else if (s.status === "cancelled") {
        addLog("INFO", "스캔이 취소되었습니다.");
        stopLiveIntervals();
      }
    } catch (err) {
      addLog("ERROR", err instanceof Error ? err.message : "상태를 가져올 수 없습니다.");
    }
  }, [sessionId]);

  useEffect(() => {
    addLog("INFO", `세션 연결: ${sessionId}`);
    addLog("OK", "원격 엔드포인트 핸드셰이크 설정 완료");
    fetchStatus();

    timerRef.current = setInterval(() => {
      elapsedRef.current += 1;
      setElapsed(formatElapsed(elapsedRef.current));
    }, 1000);

    pollRef.current = setInterval(fetchStatus, 3000);

    return () => {
      stopLiveIntervals();
    };
  }, [fetchStatus, sessionId]);

  // 300ms마다 큐에서 결과 꺼내서 표시 (running 중에만 사용)
  useEffect(() => {
    const dequeue = setInterval(() => {
      if (pendingQueue.current.length === 0) return;
      const next = pendingQueue.current.shift()!;
      setDisplayedResults((prev) => [next, ...prev]); // 최신이 위에
    }, 300);
    return () => clearInterval(dequeue);
  }, []);

  // 새 결과 추가 시 피드 맨 위로 스크롤
  useEffect(() => {
    if (feedRef.current && displayedResults.length > 0) {
      feedRef.current.scrollTo({ top: 0, behavior: "smooth" });
    }
  }, [displayedResults.length]);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  const progress = status
    ? status.total_tests > 0
      ? Math.round((status.completed_tests / status.total_tests) * 100)
      : 0
    : 0;

  const strokeDash = (progress / 100) * 100.53;
  const isRunning =
    status?.status === "queued" || status?.status === "running" || status?.status === "pending";
  const isDone = status?.status === "completed";

  return (
    <DashboardLayout>
      <style>{`
        @keyframes slideInUp {
          from { opacity: 0; transform: translateY(16px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes slideInLeft {
          from { opacity: 0; transform: translateX(-8px); }
          to   { opacity: 1; transform: translateX(0); }
        }
        @keyframes fadeIn {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
      `}</style>

      <div className="p-10 space-y-6 max-w-[1700px] mx-auto w-full">

        {/* 상단 상태 바 */}
        <div className="glass-panel p-6 rounded-[2rem] flex items-center justify-between shadow-xl">
          <div className="flex items-center gap-6">
            <div className="relative flex items-center justify-center w-12 h-12 rounded-2xl bg-primary/10">
              {isRunning && <div className="w-4 h-4 rounded-full bg-primary animate-ping absolute opacity-40" />}
              <div className={`w-2.5 h-2.5 rounded-full relative ${isDone ? "bg-tertiary" : isRunning ? "bg-primary neon-glow-primary" : "bg-error"}`} />
            </div>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-[0.25em] text-primary/80 mb-0.5">
                {isRunning ? "Scanning Live Endpoint..." : isDone ? "Scan Complete" : "Scan Failed"}
              </p>
              <p className="text-2xl font-black tracking-tight text-on-surface font-headline">
                세션 ID: <span className="text-primary font-mono text-lg">{sessionId.slice(0, 8).toUpperCase()}</span>
              </p>
            </div>
          </div>
          <div className="flex gap-8 items-center pr-4">
            <div className="text-right">
              <p className="text-[9px] font-bold text-on-surface-variant/50 uppercase tracking-widest mb-1">ELAPSED TIME</p>
              <p className="text-2xl font-mono font-medium text-on-surface tracking-tighter">{elapsed}</p>
            </div>
            {isDone ? (
              <button
                onClick={() => router.push(`/report/${sessionId}`)}
                className="h-12 px-6 rounded-xl flex items-center gap-2 font-black text-sm transition-all"
                style={{
                  background: "linear-gradient(135deg, #0ea5a5 0%, #14b8a6 100%)",
                  color: "#fff",
                  boxShadow: "0 0 20px rgba(14,165,165,0.5), 0 4px 12px rgba(0,0,0,0.3)",
                  border: "1px solid rgba(14,165,165,0.6)",
                  letterSpacing: "0.05em",
                }}
                onMouseEnter={e => (e.currentTarget.style.boxShadow = "0 0 32px rgba(14,165,165,0.75), 0 4px 16px rgba(0,0,0,0.4)")}
                onMouseLeave={e => (e.currentTarget.style.boxShadow = "0 0 20px rgba(14,165,165,0.5), 0 4px 12px rgba(0,0,0,0.3)")}
              >
                <span className="material-symbols-outlined text-base" style={{ fontVariationSettings: "'FILL' 1" }}>picture_as_pdf</span>보고서 보기
              </button>
            ) : (
              <button
                onClick={async () => {
                  stopLiveIntervals();
                  try {
                    const cancelled = await cancelScan(sessionId);
                    setStatus((prev) => prev ? { ...prev, status: cancelled.status === "cancelling" ? "cancelled" : cancelled.status } : prev);
                    addLog("INFO", "스캔 취소 요청 전송됨");
                  } catch {
                    addLog("ERROR", "스캔 취소 요청 실패");
                  }
                }}
                className="p-3.5 h-12 w-12 rounded-xl bg-error/10 text-error flex items-center justify-center hover:bg-error/20 transition-all border border-error/20"
              >
                <span className="material-symbols-outlined" style={{ fontVariationSettings: "'FILL' 1" }}>stop</span>
              </button>
            )}
          </div>
        </div>

        {/* LangGraph 파이프라인 시각화 */}
        {status && (
          <PipelineFlowViz
            phase={status.phase}
            status={status.status}
            vulnerableCount={status.vulnerable_count}
            completedTests={status.completed_tests}
            latestAttackPrompt={latestAttackPrompt}
          />
        )}

        {/* 메인 2-컬럼 레이아웃 */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

          {/* 왼쪽: 진행률 + 통계 + 터미널 */}
          <div className="lg:col-span-4 flex flex-col gap-6">

            {/* 진행률 */}
            <div className="glass-panel p-6 rounded-[2rem] flex flex-col items-center justify-center gap-5 relative overflow-hidden">
              <div className="absolute -bottom-8 -left-8 w-28 h-28 bg-primary/5 rounded-full blur-2xl" />
              <div className="relative w-32 h-32">
                <svg className="w-full h-full -rotate-90 drop-shadow-[0_0_15px_rgba(14,165,165,0.45)]" viewBox="0 0 36 36">
                  <defs>
                    <linearGradient id="progGrad" x1="0%" x2="100%" y1="0%" y2="0%">
                      <stop offset="0%" stopColor="#0A7272" /><stop offset="100%" stopColor="#2DD4D4" />
                    </linearGradient>
                  </defs>
                  <circle className="stroke-surface-container-highest" cx="18" cy="18" fill="none" r="16" strokeWidth="2.5" />
                  <circle cx="18" cy="18" fill="none" r="16" stroke="url(#progGrad)"
                    strokeDasharray={`${strokeDash}, 100.53`} strokeLinecap="round" strokeWidth="2.5"
                    className="transition-all duration-1000 ease-out" />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-on-surface tracking-tighter">{progress}%</span>
                  <span className="text-[9px] text-primary font-bold uppercase tracking-[0.2em] mt-0.5">완료율</span>
                </div>
              </div>
              <div className="text-center">
                <p className="text-xs font-semibold text-on-surface-variant/70 mb-1">전체 테스트 진행 현황</p>
                <p className="text-sm font-mono font-bold text-on-surface">
                  {status?.completed_tests ?? 0}<span className="text-on-surface-variant/40 mx-1">/</span>
                  {status?.total_tests ?? 0}<span className="text-[10px] uppercase ml-1 opacity-60">VECTORS</span>
                </p>
                {status?.phase && (
                  <p className="text-[10px] text-primary/70 mt-1.5 font-bold uppercase tracking-wider">{PHASE_LABELS[status.phase]}</p>
                )}
              </div>
              {/* 인라인 통계 */}
              <div className="w-full grid grid-cols-3 gap-3 pt-2 border-t border-white/5">
                <div className="text-center p-3 rounded-xl bg-error/5 border border-error/10">
                  <p className="text-2xl font-black text-error">{status?.vulnerable_count ?? 0}</p>
                  <p className="text-[9px] text-error/60 font-bold uppercase tracking-wider mt-0.5">취약</p>
                </div>
                <div className="text-center p-3 rounded-xl bg-white/[0.03] border border-white/10">
                  <p className="text-2xl font-black text-on-surface-variant">{status?.ambiguous_count ?? 0}</p>
                  <p className="text-[9px] text-on-surface-variant/60 font-bold uppercase tracking-wider mt-0.5">모호</p>
                </div>
                <div className="text-center p-3 rounded-xl bg-tertiary/5 border border-tertiary/10">
                  <p className="text-2xl font-black text-tertiary">{status?.safe_count ?? 0}</p>
                  <p className="text-[9px] text-tertiary/60 font-bold uppercase tracking-wider mt-0.5">안전</p>
                </div>
              </div>
            </div>

            {/* 터미널 로그 */}
            <div className="glass-panel rounded-[2rem] border border-white/5 overflow-hidden flex flex-col flex-1 min-h-[280px] max-h-[560px] shadow-xl">
              <div className="px-6 py-4 bg-surface-container-high/40 border-b border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex gap-1.5">
                    <div className="w-2 h-2 rounded-full bg-error/30" />
                    <div className="w-2 h-2 rounded-full bg-primary/30" />
                    <div className="w-2 h-2 rounded-full bg-tertiary/30" />
                  </div>
                  <span className="text-[9px] font-bold text-on-surface uppercase tracking-[0.2em]">Live Terminal</span>
                </div>
                <span className="px-2.5 py-0.5 rounded-full bg-surface-container-highest/50 text-[8px] font-mono text-on-surface-variant border border-white/5">
                  {isRunning ? "ACTIVE" : isDone ? "DONE" : "IDLE"}
                </span>
              </div>
              <div ref={logRef} className="p-5 font-mono text-[10px] overflow-y-auto space-y-1.5 flex-1 bg-[#0E0819]/80 scroll-smooth">
                {isRunning && <div className="scan-line" />}
                {logs.map((log, i) => (
                  <div key={i} className={`flex gap-4 ${log.alert ? "py-1.5 px-2.5 rounded-lg bg-error/10 border-l-2 border-error -mx-2 my-1.5" : ""}`}>
                    <span className="text-on-surface-variant/20 select-none min-w-[58px]">{log.time}</span>
                    <span className={log.levelCls}>[{log.level}]</span>
                    <span className={log.alert ? "text-on-error-container font-bold" : "text-on-surface-variant/70"}>
                      {log.msg}
                      {log.count && log.count > 1 && (
                        <span className="ml-2 text-on-surface-variant/40 font-mono text-[9px]">× {log.count}</span>
                      )}
                    </span>
                  </div>
                ))}
                {isRunning && (
                  <div className="flex gap-4">
                    <span className="text-on-surface-variant/20 select-none min-w-[58px]">--:--:--</span>
                    <span className="text-primary animate-pulse">▋</span>
                    <span className="text-on-surface-variant/50 italic">수신 대기 중...</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* 오른쪽: 실시간 결과 피드 */}
          <div className="lg:col-span-8 flex flex-col gap-4">
            {/* 피드 헤더 */}
            <div className="glass-panel flex items-center justify-between gap-4 rounded-2xl border border-white/10 px-5 py-4 shadow-lg">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="material-symbols-outlined text-primary" style={{ fontVariationSettings: "'FILL' 1" }}>dynamic_feed</span>
                  <span className="font-headline text-sm font-black uppercase tracking-[0.18em] text-on-surface">
                    실시간 결과 피드
                  </span>
                  {isRunning && (
                    <span className="rounded-full border border-primary/20 bg-primary/10 px-2.5 py-1 text-[10px] font-black text-primary">
                      LIVE
                    </span>
                  )}
                </div>
                <p className="mt-1 text-xs text-on-surface-variant/55">
                  시드 공격, Red Agent 라운드, Judge 판정, Blue 방어 검증을 최신순으로 추적합니다.
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-3">
                {isRunning && pendingQueue.current.length > 0 && (
                  <span className="animate-pulse rounded-full border border-primary/20 bg-primary/10 px-2.5 py-1 text-[10px] font-bold text-primary">
                    +{pendingQueue.current.length} 대기 중
                  </span>
                )}
                <div className="rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-right font-mono">
                  <p className="text-[10px] text-on-surface-variant/45">VISIBLE</p>
                  <p className="text-sm font-black text-on-surface">{displayedResults.length}</p>
                </div>
              </div>
            </div>

            {/* 피드 본체 */}
            <div
              ref={feedRef}
              className="flex flex-col gap-4 overflow-y-auto pr-1"
              style={{ maxHeight: "calc(100vh - 420px)", minHeight: "400px" }}
            >
              {displayedResults.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center py-20 text-on-surface-variant/30">
                  <span className="material-symbols-outlined text-5xl mb-4 opacity-20">radar</span>
                  <p className="text-sm font-bold">
                    {isRunning ? "공격 결과 수신 대기 중..." : "결과가 없습니다"}
                  </p>
                  {isRunning && (
                    <p className="text-[10px] mt-1 opacity-60">스캔이 진행되면 여기에 순차적으로 표시됩니다</p>
                  )}
                </div>
              ) : (
                displayedResults.map((r, i) => (
                  <ResultCard key={r.id} result={r} index={displayedResults.length - 1 - i} />
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
