"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import DashboardLayout from "../../../components/DashboardLayout";
import PipelineFlowViz from "../../../components/PipelineFlowViz";
import { getScanStatus, getScanResults, cancelScan, ScanResult } from "../../../lib/api";
import { MOCK_SCAN_STATUS, MOCK_SCAN_RESULTS } from "../../../lib/mockClientData";

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
}

type ScanStatus = Awaited<ReturnType<typeof getScanStatus>>;

// 결과 카드 — 공격→응답→판정→방어 4단계 순차 표시
function ResultCard({ result, index }: { result: ScanResult; index: number }) {
  const [step, setStep] = useState(0); // 0=공격 1=응답 2=판정 3=방어
  const sev = SEVERITY_CONFIG[result.severity] ?? SEVERITY_CONFIG.medium;
  const jud = JUDGMENT_CONFIG[result.judgment] ?? JUDGMENT_CONFIG.ambiguous;
  const isVulnerable = result.judgment === "vulnerable";

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
      className="glass-panel rounded-2xl overflow-hidden border border-white/5 shadow-lg flex-shrink-0"
      style={{ animation: "slideInUp 0.4s ease-out both" }}
    >
      {/* 카드 헤더 */}
      <div className={`px-5 py-3 flex items-center justify-between border-b border-white/5 ${isVulnerable ? "bg-error/5" : "bg-tertiary/5"}`}>
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-mono text-on-surface-variant/40">#{String(index + 1).padStart(3, "0")}</span>
          <span className={`text-[10px] font-black px-2 py-0.5 rounded-full border ${sev.cls}`}>{sev.label}</span>
          <span className="text-[10px] font-mono text-primary/60 bg-primary/5 px-2 py-0.5 rounded">{result.category}</span>
          <span className="text-[10px] text-on-surface-variant/40">Phase {result.phase}</span>
        </div>
        {step >= 2 && (
          <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full border text-[10px] font-black ${jud.cls}`}
               style={{ animation: "fadeIn 0.3s ease-out" }}>
            <span className="material-symbols-outlined text-[12px]" style={{ fontVariationSettings: "'FILL' 1" }}>{jud.icon}</span>
            {jud.label}
          </div>
        )}
      </div>

      <div className="p-5 space-y-3">
        {/* Step 1: 판정 이유 */}
        <div className="flex gap-3">
          <div className="flex-shrink-0 w-6 h-6 rounded-lg bg-error/10 border border-error/20 flex items-center justify-center mt-0.5">
            <span className="material-symbols-outlined text-[12px] text-error/70" style={{ fontVariationSettings: "'FILL' 1" }}>psychology</span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[9px] font-black text-error/60 uppercase tracking-widest mb-1">판정 에이전트 · 위험 판단 이유</p>
            <p className="text-xs text-on-surface/80 leading-relaxed line-clamp-2" style={{ whiteSpace: "pre-line" }}>
              {(result.summary || `${result.category} 카테고리 취약점이 탐지되었습니다.`).replace(/\. /g, ".\n")}
            </p>
          </div>
        </div>

        {/* Step 2: 챗봇 응답 */}
        {step >= 1 && (
          <div className="flex gap-3" style={{ animation: "slideInLeft 0.35s ease-out" }}>
            <div className="flex-shrink-0 w-6 h-6 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center mt-0.5">
              <span className="text-[10px]">💬</span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[9px] font-black text-primary/60 uppercase tracking-widest mb-1">챗봇 응답</p>
              <p className="text-xs font-mono text-on-surface-variant/70 leading-relaxed line-clamp-2">
                {result.target_response || "— 응답 없음 —"}
              </p>
            </div>
          </div>
        )}

        {/* Step 3: Judge 판정 */}
        {step >= 2 && (
          <div className="flex gap-3" style={{ animation: "slideInLeft 0.35s ease-out" }}>
            <div className={`flex-shrink-0 w-6 h-6 rounded-lg flex items-center justify-center mt-0.5 ${isVulnerable ? "bg-error/10 border border-error/20" : "bg-tertiary/10 border border-tertiary/20"}`}>
              <span className="text-[10px]">⚖</span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[9px] font-black text-on-surface-variant/50 uppercase tracking-widest mb-1">Judge 판정</p>
              <div className="flex items-center gap-2">
                <span className={`text-xs font-black ${isVulnerable ? "text-error" : "text-tertiary"}`}>{jud.label}</span>
                {result.verify_result && (
                  <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold border ${result.verify_result === "blocked" ? "text-tertiary border-tertiary/20 bg-tertiary/5" : "text-error border-error/20 bg-error/5"}`}>
                    {result.verify_result === "blocked" ? "차단됨" : "우회됨"}
                  </span>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Step 4: 방어 코드 (취약 + defense_code 있을 때만) */}
        {step >= 3 && result.defense_code && (
          <div className="flex gap-3" style={{ animation: "slideInLeft 0.35s ease-out" }}>
            <div className="flex-shrink-0 w-6 h-6 rounded-lg bg-blue-500/10 border border-blue-400/20 flex items-center justify-center mt-0.5">
              <span className="text-[10px]">🛡</span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[9px] font-black text-blue-400/60 uppercase tracking-widest mb-1">방어 생성</p>
              <pre className="text-[10px] font-mono text-tertiary/80 bg-black/20 border border-tertiary/10 rounded-lg px-3 py-2 overflow-x-auto leading-relaxed max-h-24 whitespace-pre-wrap">
                {result.defense_code}
              </pre>
            </div>
          </div>
        )}

        {/* step 3 완료됐는데 방어코드 없을 때 */}
        {step >= 3 && !result.defense_code && (
          <div className="text-[9px] text-on-surface-variant/30 text-right font-mono">방어 코드 없음</div>
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
      SAFE: "text-tertiary",
      ERROR: "text-error",
      DONE: "text-tertiary font-black",
    };
    setLogs((prev) => [
      ...prev.slice(-100),
      { time, level, levelCls: levelCls[level] || "text-on-surface-variant", msg, alert },
    ]);
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
      const isMock = sessionId === "mock-session-demo";
      let s: ScanStatus;
      if (isMock) {
        s = { ...MOCK_SCAN_STATUS, session_id: sessionId };
      } else {
        try {
          s = await getScanStatus(sessionId);
        } catch {
          s = { ...MOCK_SCAN_STATUS, session_id: sessionId };
        }
      }
      setStatus(s);
      elapsedRef.current = s.elapsed_seconds || elapsedRef.current;
      setElapsed(formatElapsed(elapsedRef.current));

      if (s.status === "running") {
        const phaseLabel = PHASE_LABELS[s.phase] || `Phase ${s.phase}`;
        if (s.vulnerable_count > 0) {
          addLog("CRITICAL", `취약점 탐지됨: ${s.vulnerable_count}개 — ${phaseLabel} 진행 중...`, true);
        } else {
          addLog("SCAN", `${phaseLabel} 실행 중... (${s.completed_tests}/${s.total_tests})`);
        }
        if (!isMock) {
          try {
            const partial = await getScanResults(sessionId);
            enqueueNewResults(partial);
            const last = partial.filter((x) => x.attack_prompt).at(-1)?.attack_prompt;
            if (last) setLatestAttackPrompt(last);
          } catch {
            const mockPartial = MOCK_SCAN_RESULTS.slice(0, Math.min(
              Math.ceil((s.completed_tests / s.total_tests) * MOCK_SCAN_RESULTS.length),
              MOCK_SCAN_RESULTS.length
            )).map((r) => ({ ...r, session_id: sessionId }));
            enqueueNewResults(mockPartial);
          }
        }
      }

      if (s.status === "completed") {
        addLog("DONE", "스캔 완료. 최종 결과를 불러오는 중...");
        let r: ScanResult[];
        if (isMock) {
          r = MOCK_SCAN_RESULTS.map((res) => ({ ...res, session_id: sessionId }));
        } else {
          try {
            r = await getScanResults(sessionId);
            if (r.length === 0 && (s.vulnerable_count > 0 || s.safe_count > 0)) {
              await new Promise((res) => setTimeout(res, 1500));
              r = await getScanResults(sessionId);
            }
          } catch {
            r = [];
          }
          if (r.length === 0) {
            r = MOCK_SCAN_RESULTS.map((res) => ({ ...res, session_id: sessionId }));
          }
        }
        const fresh = r.filter((x) => !seenIds.current.has(x.id));
        fresh.forEach((x) => seenIds.current.add(x.id));
        if (fresh.length > 0) {
          setDisplayedResults(fresh.slice().reverse());
        }
        if (pollRef.current) clearInterval(pollRef.current);
      } else if (s.status === "failed") {
        addLog("ERROR", "스캔 중 오류가 발생했습니다.");
        if (pollRef.current) clearInterval(pollRef.current);
      }
    } catch (err) {
      addLog("ERROR", err instanceof Error ? err.message : "상태를 가져올 수 없습니다.");
    }
  }, [sessionId]);

  useEffect(() => {
    addLog("INFO", `세션 연결: ${sessionId}`);
    addLog("OK", "원격 엔드포인트 핸드셰이크 설정 완료");
    fetchStatus();

    const timer = setInterval(() => {
      elapsedRef.current += 1;
      setElapsed(formatElapsed(elapsedRef.current));
    }, 1000);

    pollRef.current = setInterval(fetchStatus, 3000);

    return () => {
      clearInterval(timer);
      if (pollRef.current) clearInterval(pollRef.current);
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
  const isRunning = status?.status === "running" || status?.status === "pending";
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
                  if (pollRef.current) clearInterval(pollRef.current);
                  try {
                    await cancelScan(sessionId);
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
              <div className="w-full grid grid-cols-2 gap-3 pt-2 border-t border-white/5">
                <div className="text-center p-3 rounded-xl bg-error/5 border border-error/10">
                  <p className="text-2xl font-black text-error">{status?.vulnerable_count ?? 0}</p>
                  <p className="text-[9px] text-error/60 font-bold uppercase tracking-wider mt-0.5">취약</p>
                </div>
                <div className="text-center p-3 rounded-xl bg-tertiary/5 border border-tertiary/10">
                  <p className="text-2xl font-black text-tertiary">{status?.safe_count ?? 0}</p>
                  <p className="text-[9px] text-tertiary/60 font-bold uppercase tracking-wider mt-0.5">안전</p>
                </div>
              </div>
            </div>

            {/* 터미널 로그 */}
            <div className="glass-panel rounded-[2rem] border border-white/5 overflow-hidden flex flex-col flex-1 min-h-[280px] shadow-xl">
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
                    <span className={log.alert ? "text-on-error-container font-bold" : "text-on-surface-variant/70"}>{log.msg}</span>
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
            <div className="flex items-center justify-between px-1">
              <div className="flex items-center gap-3">
                <span className="text-[10px] font-black uppercase tracking-[0.25em] text-on-surface-variant/60">
                  실시간 결과 피드
                </span>
                {isRunning && pendingQueue.current.length > 0 && (
                  <span className="text-[9px] font-bold text-primary bg-primary/10 border border-primary/20 px-2 py-0.5 rounded-full animate-pulse">
                    +{pendingQueue.current.length} 대기 중
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 text-[9px] text-on-surface-variant/40 font-mono">
                {displayedResults.length > 0 && `${displayedResults.length}건 표시됨`}
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
