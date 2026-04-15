"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import DashboardLayout from "../../../components/DashboardLayout";
import { getScanStatus, getScanResults, ScanResult } from "../../../lib/api";

const PHASE_LABELS: Record<number, string> = {
  1: "Phase 1 — 정적 스캐너",
  2: "Phase 2 — Red Agent 공격",
  3: "Phase 3 — Blue Agent 방어",
  4: "Phase 4 — 검증",
};

const SEVERITY_CONFIG: Record<string, { cls: string; label: string }> = {
  critical: { cls: "bg-error/10 text-error border-error/20", label: "긴급" },
  high: { cls: "bg-primary/10 text-primary border-primary/20", label: "높음" },
  medium: { cls: "bg-outline/10 text-on-surface-variant border-outline/20", label: "중간" },
  low: { cls: "bg-tertiary/10 text-tertiary border-tertiary/20", label: "낮음" },
};

interface LogEntry {
  time: string;
  level: string;
  levelCls: string;
  msg: string;
  alert?: boolean;
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

  const [results, setResults] = useState<ScanResult[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const [severityFilter, setSeverityFilter] = useState("");
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

  const fetchStatus = useCallback(async () => {
    try {
      const s = await getScanStatus(sessionId);
      setStatus(s);
      elapsedRef.current = s.elapsed_seconds || elapsedRef.current;
      setElapsed(formatElapsed(elapsedRef.current));

      // 로그 생성
      if (s.status === "running") {
        const phaseLabel = PHASE_LABELS[s.phase] || `Phase ${s.phase}`;
        if (s.vulnerable_count > 0) {
          addLog("CRITICAL", `취약점 탐지됨: ${s.vulnerable_count}개 — ${phaseLabel} 진행 중...`, true);
        } else {
          addLog("SCAN", `${phaseLabel} 실행 중... (${s.completed_tests}/${s.total_tests})`);
        }
      }

      if (s.status === "completed") {
        addLog("DONE", "스캔 완료. 최종 결과를 불러오는 중...");
        const r = await getScanResults(sessionId);
        setResults(r);
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

    // 타이머
    const timer = setInterval(() => {
      elapsedRef.current += 1;
      setElapsed(formatElapsed(elapsedRef.current));
    }, 1000);

    // 상태 폴링 (3초마다)
    pollRef.current = setInterval(fetchStatus, 3000);

    return () => {
      clearInterval(timer);
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [fetchStatus, sessionId]);

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

  const strokeDash = (progress / 100) * 100.53; // circumference for r=16
  const isRunning = status?.status === "running" || status?.status === "pending";
  const isDone = status?.status === "completed";

  const filteredResults = results.filter(
    (r) => !severityFilter || r.severity === severityFilter
  );

  return (
    <DashboardLayout>
      <div className="p-10 space-y-8 max-w-[1700px] mx-auto w-full">
        {/* 상단 상태 바 */}
        <div className="glass-panel p-6 rounded-[2rem] flex items-center justify-between shadow-xl">
          <div className="flex items-center gap-6">
            <div className="relative flex items-center justify-center w-12 h-12 rounded-2xl bg-primary/10">
              {isRunning && (
                <div className="w-4 h-4 rounded-full bg-primary animate-ping absolute opacity-40" />
              )}
              <div
                className={`w-2.5 h-2.5 rounded-full relative ${
                  isDone ? "bg-tertiary" : isRunning ? "bg-primary neon-glow-primary" : "bg-error"
                }`}
              />
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
              <p className="text-[9px] font-bold text-on-surface-variant/50 uppercase tracking-widest mb-1">
                ELAPSED TIME
              </p>
              <p className="text-2xl font-mono font-medium text-on-surface tracking-tighter">
                {elapsed}
              </p>
            </div>
            {isDone ? (
              <button
                onClick={() => router.push(`/report/${sessionId}`)}
                className="h-12 px-5 rounded-xl bg-tertiary/10 text-tertiary flex items-center gap-2 hover:bg-tertiary/20 transition-all border border-tertiary/20 font-bold text-sm"
              >
                <span className="material-symbols-outlined text-sm">picture_as_pdf</span>
                보고서
              </button>
            ) : (
              <button
                onClick={() => { if (pollRef.current) clearInterval(pollRef.current); }}
                className="p-3.5 h-12 w-12 rounded-xl bg-error/10 text-error flex items-center justify-center hover:bg-error/20 transition-all border border-error/20"
              >
                <span className="material-symbols-outlined" style={{ fontVariationSettings: "'FILL' 1" }}>
                  stop
                </span>
              </button>
            )}
          </div>
        </div>

        {/* 진행률 + 통계 + 로그 */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* 원형 진행률 */}
          <div className="md:col-span-5 p-8 rounded-[2rem] glass-panel flex flex-col items-center justify-center gap-6 relative overflow-hidden">
            <div className="absolute -bottom-10 -left-10 w-32 h-32 bg-primary/5 rounded-full blur-2xl" />
            <div className="relative w-40 h-40">
              <svg className="w-full h-full -rotate-90 drop-shadow-[0_0_15px_rgba(152,203,255,0.3)]" viewBox="0 0 36 36">
                <defs>
                  <linearGradient id="progGrad" x1="0%" x2="100%" y1="0%" y2="0%">
                    <stop offset="0%" stopColor="#98cbff" />
                    <stop offset="100%" stopColor="#00a3ff" />
                  </linearGradient>
                </defs>
                <circle className="stroke-surface-container-highest" cx="18" cy="18" fill="none" r="16" strokeWidth="2.5" />
                <circle
                  cx="18" cy="18" fill="none" r="16"
                  stroke="url(#progGrad)"
                  strokeDasharray={`${strokeDash}, 100.53`}
                  strokeLinecap="round"
                  strokeWidth="2.5"
                  className="transition-all duration-1000 ease-out"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-4xl font-black text-on-surface tracking-tighter">{progress}%</span>
                <span className="text-[10px] text-primary font-bold uppercase tracking-[0.2em] mt-1">완료율</span>
              </div>
            </div>
            <div className="text-center">
              <p className="text-xs font-semibold text-on-surface-variant/70 mb-1">전체 테스트 진행 현황</p>
              <p className="text-sm font-mono font-bold text-on-surface">
                {status?.completed_tests ?? 0}
                <span className="text-on-surface-variant/40 mx-1">/</span>
                {status?.total_tests ?? 0}
                <span className="text-[10px] uppercase ml-1 opacity-60">VECTORS</span>
              </p>
              {status?.phase && (
                <p className="text-[10px] text-primary/70 mt-2 font-bold uppercase tracking-wider">
                  {PHASE_LABELS[status.phase]}
                </p>
              )}
            </div>
          </div>

          {/* 통계 그리드 */}
          <div className="md:col-span-7 grid grid-cols-2 gap-6">
            <div className="p-6 rounded-[2rem] bg-surface-container-low/40 border border-white/10 flex flex-col justify-between hover:border-primary/20 transition-colors">
              <span className="text-[10px] font-bold uppercase text-on-surface-variant/60 tracking-widest">공격 횟수</span>
              <div className="mt-4">
                <p className="text-5xl font-black tracking-tight text-primary">
                  {(status?.completed_tests ?? 0).toLocaleString()}
                </p>
                <div className="flex items-center gap-1.5 text-[10px] text-tertiary mt-2 font-bold bg-tertiary/10 w-fit px-2 py-0.5 rounded-full">
                  <span className="material-symbols-outlined text-[10px]">trending_up</span>
                  ACTIVE
                </div>
              </div>
            </div>
            <div className="p-6 rounded-[2rem] bg-error-container/5 border border-error/20 flex flex-col justify-between relative overflow-hidden group">
              <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                <span className="material-symbols-outlined text-4xl text-error">warning</span>
              </div>
              <span className="text-[10px] font-bold uppercase text-error tracking-widest">탐지된 취약점</span>
              <div className="mt-4">
                <p className="text-5xl font-black tracking-tight text-error neon-glow-error">
                  {status?.vulnerable_count ?? 0}
                </p>
                {(status?.vulnerable_count ?? 0) > 0 && (
                  <div className="text-[10px] text-error font-bold mt-2 uppercase tracking-tighter animate-pulse">
                    Security Risk Detected
                  </div>
                )}
              </div>
            </div>
            <div className="col-span-2 p-6 rounded-[2.5rem] bg-tertiary-container/5 border border-tertiary/20 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-tertiary/10 flex items-center justify-center text-tertiary">
                  <span className="material-symbols-outlined">verified_user</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold uppercase text-tertiary/80 tracking-widest">안전 검증됨</span>
                  <p className="text-2xl font-black tracking-tight text-on-surface">
                    {status?.safe_count ?? 0}{" "}
                    <span className="text-sm font-medium text-on-surface-variant ml-1">테스트 케이스</span>
                  </p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-[10px] font-medium text-tertiary/70 uppercase">Mitigation Status</p>
                <p className="text-xs font-bold text-on-surface">보안 필터링 활성</p>
              </div>
            </div>
          </div>
        </div>

        {/* 터미널 로그 */}
        <div className="glass-panel rounded-[2rem] border border-white/5 overflow-hidden flex flex-col h-[380px] shadow-2xl relative">
          <div className="px-8 py-5 bg-surface-container-high/40 border-b border-white/5 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-error/30" />
                <div className="w-2.5 h-2.5 rounded-full bg-primary/30" />
                <div className="w-2.5 h-2.5 rounded-full bg-tertiary/30" />
              </div>
              <div className="h-4 w-px bg-white/10 mx-2" />
              <span className="text-[10px] font-bold text-on-surface uppercase tracking-[0.2em]">
                Live Terminal Feed
              </span>
            </div>
            <div className="flex gap-4">
              <span className="px-3 py-1 rounded-full bg-surface-container-highest/50 text-[9px] font-mono text-on-surface-variant font-medium border border-white/5">
                {isRunning ? "SCANNING ACTIVE" : isDone ? "SCAN COMPLETE" : "IDLE"}
              </span>
            </div>
          </div>
          <div
            ref={logRef}
            className="p-8 font-mono text-[11px] overflow-y-auto space-y-2 flex-1 bg-[#010e24]/80 relative scroll-smooth"
          >
            {isRunning && <div className="scan-line" />}
            {logs.map((log, i) => (
              <div
                key={i}
                className={`flex gap-6 group ${
                  log.alert
                    ? "py-2 px-3 rounded-lg bg-error/10 border-l-2 border-error neon-glow-error -mx-3 my-2"
                    : ""
                }`}
              >
                <span className="text-on-surface-variant/20 select-none min-w-[70px]">{log.time}</span>
                <span className={log.levelCls}>[{log.level}]</span>
                <span className={log.alert ? "text-on-error-container font-bold" : "text-on-surface-variant/80"}>
                  {log.msg}
                </span>
              </div>
            ))}
            {isRunning && (
              <div className="flex gap-6">
                <span className="text-on-surface-variant/20 select-none min-w-[70px]">--:--:--</span>
                <span className="text-primary animate-pulse">▋</span>
                <span className="text-on-surface-variant/60 italic">수신 결과를 기다리는 중...</span>
              </div>
            )}
          </div>
        </div>

        {/* 결과 테이블 (완료 후) */}
        {isDone && results.length > 0 && (
          <div className="glass-panel rounded-[2rem] overflow-hidden shadow-2xl">
            <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between">
              <h3 className="font-headline font-bold text-xl flex items-center gap-3 text-white">
                <span className="material-symbols-outlined text-error">gpp_bad</span>
                취약점 분석 결과
              </h3>
              <div className="flex items-center gap-3">
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-surface-container border border-white/10 rounded-xl text-xs px-3 py-2 text-on-surface focus:outline-none focus:border-primary/40"
                >
                  <option value="">전체 심각도</option>
                  <option value="critical">긴급</option>
                  <option value="high">높음</option>
                  <option value="medium">중간</option>
                  <option value="low">낮음</option>
                </select>
                <span className="text-[10px] font-bold uppercase tracking-widest text-error bg-error/10 border border-error/20 px-3 py-1.5 rounded-lg">
                  {filteredResults.length} 건
                </span>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-black/20 text-on-surface-variant text-[10px] uppercase tracking-widest font-extrabold">
                  <tr>
                    <th className="px-6 py-4 border-b border-white/5">카테고리</th>
                    <th className="px-6 py-4 border-b border-white/5">심각도</th>
                    <th className="px-6 py-4 border-b border-white/5">판정</th>
                    <th className="px-6 py-4 border-b border-white/5">검증 결과</th>
                    <th className="px-6 py-4 border-b border-white/5">공격 프롬프트</th>
                    <th className="px-6 py-4 border-b border-white/5 text-center">방어코드</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filteredResults.map((r) => {
                    const sev = SEVERITY_CONFIG[r.severity] || SEVERITY_CONFIG.medium;
                    return (
                      <tr
                        key={r.id}
                        onClick={() => setSelectedResult(r)}
                        className="row-glow transition-all cursor-pointer group hover:bg-white/2"
                      >
                        <td className="px-6 py-4">
                          <span className="font-mono text-[10px] text-primary/70 bg-primary/5 px-2 py-1 rounded">
                            {r.category}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider border ${sev.cls}`}>
                            {sev.label}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`text-xs font-bold uppercase ${
                              r.judgment === "vulnerable" ? "text-error" : r.judgment === "safe" ? "text-tertiary" : "text-on-surface-variant"
                            }`}
                          >
                            {r.judgment === "vulnerable" ? "취약" : r.judgment === "safe" ? "안전" : "모호"}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`text-xs font-bold uppercase ${
                              r.verify_result === "blocked" ? "text-tertiary" : r.verify_result === "bypassed" ? "text-error" : "text-on-surface-variant"
                            }`}
                          >
                            {r.verify_result || "—"}
                          </span>
                        </td>
                        <td className="px-6 py-4 max-w-xs">
                          <p className="text-xs text-on-surface-variant truncate font-mono">
                            {r.attack_prompt}
                          </p>
                        </td>
                        <td className="px-6 py-4 text-center">
                          {r.defense_code ? (
                            <span className="material-symbols-outlined text-tertiary text-lg" style={{ fontVariationSettings: "'FILL' 1" }}>
                              check_circle
                            </span>
                          ) : (
                            <span className="material-symbols-outlined text-on-surface-variant/30 text-lg">
                              remove
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 결과 상세 드로어 */}
        {selectedResult && (
          <div className="fixed inset-0 z-[60] flex" onClick={() => setSelectedResult(null)}>
            <div className="absolute inset-0 bg-background/60 backdrop-blur-sm" />
            <div
              className="fixed right-4 top-4 bottom-4 w-[480px] glass-panel rounded-3xl shadow-2xl z-[70] flex flex-col border border-white/10"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="p-8 flex items-center justify-between border-b border-white/5">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-error/10 border border-error/20 rounded-2xl flex items-center justify-center">
                    <span className="material-symbols-outlined text-error text-2xl" style={{ fontVariationSettings: "'FILL' 1" }}>
                      bug_report
                    </span>
                  </div>
                  <div>
                    <h3 className="text-xl font-black font-headline text-on-surface tracking-tight">
                      취약점 상세
                    </h3>
                    <p className="text-[10px] text-primary font-mono tracking-widest uppercase mt-0.5">
                      {selectedResult.category} / {selectedResult.severity.toUpperCase()}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedResult(null)}
                  className="p-2.5 hover:bg-white/10 rounded-xl transition-all text-on-surface-variant"
                >
                  <span className="material-symbols-outlined">close</span>
                </button>
              </div>
              <div className="flex-1 overflow-y-auto p-8 space-y-8">
                <div className="space-y-3">
                  <p className="text-[10px] font-black text-outline tracking-widest uppercase flex items-center gap-2">
                    <span className="w-1.5 h-1.5 bg-error rounded-full" /> 공격 프롬프트
                  </p>
                  <div className="bg-black/30 p-5 rounded-2xl font-mono text-xs text-on-surface border border-white/5 leading-relaxed">
                    {selectedResult.attack_prompt}
                  </div>
                </div>
                <div className="space-y-3">
                  <p className="text-[10px] font-black text-outline tracking-widest uppercase flex items-center gap-2">
                    <span className="w-1.5 h-1.5 bg-primary rounded-full" /> 대상 응답
                  </p>
                  <div className="bg-black/30 p-5 rounded-2xl font-mono text-xs text-on-surface-variant border border-white/5 leading-relaxed max-h-40 overflow-y-auto">
                    {selectedResult.target_response || "응답 없음"}
                  </div>
                </div>
                {selectedResult.defense_code && (
                  <div className="space-y-3">
                    <p className="text-[10px] font-black text-outline tracking-widest uppercase flex items-center gap-2">
                      <span className="w-1.5 h-1.5 bg-tertiary rounded-full" /> 방어 코드 제안
                    </p>
                    <div className="bg-black/30 p-5 rounded-2xl font-mono text-xs text-tertiary border border-tertiary/10 leading-relaxed max-h-60 overflow-y-auto whitespace-pre-wrap">
                      {selectedResult.defense_code}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
