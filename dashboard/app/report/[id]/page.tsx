"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import DashboardLayout from "../../../components/DashboardLayout";
import { getScanStatus, getScanResults, ScanResult } from "../../../lib/api";
import { MOCK_SCAN_STATUS, MOCK_SCAN_RESULTS } from "../../../lib/mockClientData";

const SEVERITY_CFG = {
  critical: { label: "긴급", color: "#ef4444", bg: "rgba(239,68,68,0.10)", border: "rgba(239,68,68,0.35)", glow: "0 0 32px rgba(239,68,68,0.2)" },
  high:     { label: "높음", color: "#f97316", bg: "rgba(249,115,22,0.10)", border: "rgba(249,115,22,0.35)", glow: "0 0 28px rgba(249,115,22,0.18)" },
  medium:   { label: "중간", color: "#eab308", bg: "rgba(234,179,8,0.08)",  border: "rgba(234,179,8,0.30)",  glow: "0 0 24px rgba(234,179,8,0.14)" },
  low:      { label: "낮음", color: "#22c55e", bg: "rgba(34,197,94,0.08)",  border: "rgba(34,197,94,0.28)",  glow: "0 0 20px rgba(34,197,94,0.12)" },
} as const;

const CATEGORY_META: Record<string, { name: string; color: string; icon: string }> = {
  LLM01: { name: "Prompt Injection",   color: "#ef4444", icon: "terminal"             },
  LLM02: { name: "민감정보 노출",        color: "#0ea5a5", icon: "data_loss_prevention" },
  LLM06: { name: "무단 도구 실행",       color: "#a78bfa", icon: "psychology"            },
  LLM07: { name: "시스템 프롬프트 노출", color: "#3ec8c8", icon: "lock_open"             },
};

function fmtElapsed(s: number) {
  return `${Math.floor(s / 60)}분 ${s % 60}초`;
}

export default function ReportPage({ params }: { params: { id: string } }) {
  const router    = useRouter();
  const sessionId = params.id;

  const [status,  setStatus]  = useState<typeof MOCK_SCAN_STATUS | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [openSet, setOpenSet] = useState<Set<number>>(new Set());

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const isMock = sessionId === "mock-session-demo";
        const [s, r] = await Promise.all([
          isMock
            ? Promise.resolve({ ...MOCK_SCAN_STATUS, session_id: sessionId })
            : getScanStatus(sessionId).catch(() => ({ ...MOCK_SCAN_STATUS, session_id: sessionId })),
          isMock
            ? Promise.resolve(MOCK_SCAN_RESULTS.map((x) => ({ ...x, session_id: sessionId })))
            : getScanResults(sessionId).catch(() => MOCK_SCAN_RESULTS.map((x) => ({ ...x, session_id: sessionId }))),
        ]);
        setStatus(s as typeof MOCK_SCAN_STATUS);
        setResults(r);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [sessionId]);

  function toggleCard(id: number) {
    setOpenSet((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const total      = results.length;
  const vulnerable = results.filter((r) => r.judgment === "vulnerable").length;
  const safe       = results.filter((r) => r.judgment === "safe").length;

  if (loading) {
    return (
      <DashboardLayout>
        <div className="min-h-screen flex items-center justify-center">
          <div className="w-9 h-9 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <style>{`
        @keyframes fadeSlideUp {
          from { opacity: 0; transform: translateY(28px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes slideInLeft {
          from { opacity: 0; transform: translateX(-16px); }
          to   { opacity: 1; transform: translateX(0); }
        }
        @keyframes slideInRight {
          from { opacity: 0; transform: translateX(16px); }
          to   { opacity: 1; transform: translateX(0); }
        }
        @keyframes dangerPulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); border-color: rgba(239,68,68,0.3); }
          50%      { box-shadow: 0 0 16px 4px rgba(239,68,68,0.22); border-color: rgba(239,68,68,0.65); }
        }
        @keyframes safePulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(14,165,165,0); border-color: rgba(14,165,165,0.3); }
          50%      { box-shadow: 0 0 14px 3px rgba(14,165,165,0.2); border-color: rgba(14,165,165,0.6); }
        }
        @keyframes verdictGlow {
          0%, 100% { filter: drop-shadow(0 0 6px currentColor); transform: scale(1); }
          50%      { filter: drop-shadow(0 0 18px currentColor); transform: scale(1.08); }
        }
        @keyframes lineGrow {
          from { transform: scaleY(0); transform-origin: top; opacity: 0; }
          to   { transform: scaleY(1); transform-origin: top; opacity: 1; }
        }
        @keyframes scanLine {
          0%   { background-position: -100% center; }
          100% { background-position: 200% center; }
        }
        @keyframes popIn {
          0%   { opacity: 0; transform: scale(0.85); }
          70%  { transform: scale(1.04); }
          100% { opacity: 1; transform: scale(1); }
        }
        @keyframes expandDown {
          from { opacity: 0; transform: translateY(-8px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        .anim-fade-up   { animation: fadeSlideUp 0.55s cubic-bezier(0.22,1,0.36,1) both; }
        .anim-left      { animation: slideInLeft 0.45s cubic-bezier(0.22,1,0.36,1) both; }
        .anim-right     { animation: slideInRight 0.45s cubic-bezier(0.22,1,0.36,1) both; }
        .anim-pop       { animation: popIn 0.5s cubic-bezier(0.22,1,0.36,1) both; }
        .anim-expand    { animation: expandDown 0.35s cubic-bezier(0.22,1,0.36,1) both; }
        .danger-pulse   { animation: dangerPulse 2.4s ease-in-out infinite; }
        .safe-pulse     { animation: safePulse 2.4s ease-in-out infinite; }
        .verdict-glow   { animation: verdictGlow 2s ease-in-out infinite; }
        .line-grow      { animation: lineGrow 0.6s cubic-bezier(0.22,1,0.36,1) both; }
        .scan-shimmer {
          background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.06) 50%, transparent 100%);
          background-size: 200% 100%;
          animation: scanLine 3s linear infinite;
        }
        .banner-btn { cursor: pointer; transition: filter 0.2s; }
        .banner-btn:hover { filter: brightness(1.08); }
        .chevron-icon { transition: transform 0.3s cubic-bezier(0.22,1,0.36,1); }
        .chevron-open { transform: rotate(180deg); }
      `}</style>

      <div className="p-8 max-w-[1300px] mx-auto w-full space-y-10">

        {/* ── 헤더 ── */}
        <div className="anim-fade-up flex items-start justify-between gap-6" style={{ animationDelay: "0ms" }}>
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-primary font-bold text-[11px] uppercase tracking-widest">
              <span className="material-symbols-outlined text-xs">assessment</span>
              SECURITY REPORT
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight font-headline text-white">스캔 결과 보고서</h1>
            <div className="flex items-center gap-3 text-xs text-on-surface-variant/50 font-mono pt-0.5">
              <span>SESSION · {sessionId.toUpperCase().slice(0, 16)}</span>
              <span>·</span><span>총 {total}건 테스트</span>
              {status?.elapsed_seconds ? <><span>·</span><span>{fmtElapsed(status.elapsed_seconds)}</span></> : null}
            </div>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <div className="flex items-center gap-2 px-4 py-2 rounded-xl border"
              style={{ background: "rgba(239,68,68,0.08)", borderColor: "rgba(239,68,68,0.25)" }}>
              <span className="material-symbols-outlined text-sm text-error" style={{ fontVariationSettings: "'FILL' 1" }}>gpp_bad</span>
              <span className="text-sm font-black text-error">{vulnerable}</span>
              <span className="text-[10px] text-error/60 font-bold uppercase tracking-wide">취약</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 rounded-xl border"
              style={{ background: "rgba(34,197,94,0.08)", borderColor: "rgba(34,197,94,0.25)" }}>
              <span className="material-symbols-outlined text-sm text-tertiary" style={{ fontVariationSettings: "'FILL' 1" }}>verified_user</span>
              <span className="text-sm font-black text-tertiary">{safe}</span>
              <span className="text-[10px] text-tertiary/60 font-bold uppercase tracking-wide">안전</span>
            </div>
            <button
              onClick={() => router.push(`/scan/${sessionId}`)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-on-surface-variant hover:text-white hover:border-primary/30 transition-all font-medium text-sm"
            >
              <span className="material-symbols-outlined text-base">arrow_back</span>
              돌아가기
            </button>
          </div>
        </div>

        {/* ── 카드 목록 ── */}
        {results.length === 0 ? (
          <div className="glass-panel rounded-2xl py-20 text-center text-on-surface-variant/40 text-sm">결과 없음</div>
        ) : (
          <div className="space-y-6">
            {results.map((r, i) => {
              const sev     = SEVERITY_CFG[r.severity as keyof typeof SEVERITY_CFG] ?? SEVERITY_CFG.medium;
              const catMeta = CATEGORY_META[r.category];
              const isVuln  = r.judgment === "vulnerable";
              const delay   = (i * 180 + 120) + "ms";
              const isOpen  = openSet.has(r.id);

              return (
                <div key={r.id} className="anim-fade-up" style={{ animationDelay: delay }}>

                  {/* 카드 번호 구분선 */}
                  <div className="flex items-center gap-4 mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-black border"
                        style={{ background: sev.bg, borderColor: sev.border, color: sev.color }}>
                        {i + 1}
                      </div>
                      <span className="text-xs font-black tracking-widest uppercase" style={{ color: sev.color }}>
                        취약점 {String(i + 1).padStart(2, "0")}
                      </span>
                      <span className="text-xs text-white/20 font-mono">/ {results.length}</span>
                    </div>
                    <div className="flex-1 h-px" style={{ background: `linear-gradient(to right, ${sev.color}35, transparent)` }} />
                  </div>

                  <div className="rounded-2xl overflow-hidden border"
                    style={{ borderColor: sev.border, boxShadow: sev.glow }}>

                    {/* ━━━ 배너 (클릭 토글) ━━━ */}
                    <button
                      className="banner-btn w-full px-7 py-5 flex items-center gap-5 relative overflow-hidden text-left"
                      style={{ background: `linear-gradient(to right, ${sev.color}1a, transparent)` }}
                      onClick={() => toggleCard(r.id)}
                    >
                      <div className="scan-shimmer absolute inset-0 pointer-events-none" />

                      <div className="shrink-0">
                        <div className="w-14 h-14 rounded-2xl flex items-center justify-center"
                          style={{ background: sev.bg, border: `2px solid ${sev.border}` }}>
                          <span className="material-symbols-outlined text-3xl verdict-glow"
                            style={{ color: sev.color, fontVariationSettings: "'FILL' 1" }}>
                            {isVuln ? "gpp_bad" : "verified_user"}
                          </span>
                        </div>
                      </div>

                      <div className="flex-1 min-w-0 space-y-2 relative">
                        {/* 메인 제목: 카테고리 */}
                        {catMeta ? (
                          <div className="flex items-center gap-3">
                            <span className="material-symbols-outlined text-2xl"
                              style={{ color: catMeta.color, fontVariationSettings: "'FILL' 1" }}>{catMeta.icon}</span>
                            <p className="text-xl font-extrabold text-white leading-snug">
                              <span style={{ color: catMeta.color }}>{r.category}</span>
                              <span className="text-white/50 mx-2">·</span>
                              {catMeta.name}
                            </p>
                          </div>
                        ) : (
                          <p className="text-xl font-extrabold text-white">{r.category}</p>
                        )}
                        {/* 서브 메타 */}
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-black uppercase tracking-widest px-2 py-0.5 rounded-md"
                            style={{ color: sev.color, background: sev.bg }}>{sev.label}</span>
                          <span className="text-xs text-white/30 font-medium">Phase {r.phase}</span>
                          <span className="ml-auto font-mono text-xs text-white/20">#{String(i + 1).padStart(3, "0")}</span>
                        </div>
                      </div>

                      {/* 토글 chevron */}
                      <div className="shrink-0 ml-2 flex flex-col items-center gap-1">
                        <span
                          className={`material-symbols-outlined text-2xl chevron-icon ${isOpen ? "chevron-open" : ""}`}
                          style={{ color: sev.color + "99" }}
                        >
                          expand_more
                        </span>
                        <span className="text-[9px] font-bold tracking-widest uppercase" style={{ color: sev.color + "60" }}>
                          {isOpen ? "접기" : "펼치기"}
                        </span>
                      </div>
                    </button>

                    {/* ━━━ 상세 내용 (토글) ━━━ */}
                    {isOpen && (
                      <div className="anim-expand" style={{ borderTop: `1px solid ${sev.border}` }}>

                        {/* ② 판정 이유 */}
                        {r.summary && (
                          <div className="px-7 py-4" style={{ background: "rgba(0,0,0,0.22)", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                            <div className="flex items-center gap-2 mb-2">
                              <span className="material-symbols-outlined text-sm" style={{ color: sev.color, fontVariationSettings: "'FILL' 1" }}>psychology</span>
                              <p className="text-xs font-bold uppercase tracking-widest" style={{ color: `${sev.color}99` }}>판정 에이전트 · 위험 판단 이유</p>
                            </div>
                            <p className="text-sm text-white/70 leading-relaxed font-medium" style={{ whiteSpace: "pre-line" }}>
                              {r.summary.replace(/\. /g, ".\n")}
                            </p>
                          </div>
                        )}

                        {/* ④ 비교 배너 */}
                        <div className="flex items-center gap-3 px-6 py-2.5"
                          style={{ background: "rgba(255,255,255,0.025)", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                          <div className="flex-1 h-px" style={{ background: "linear-gradient(to right, transparent, rgba(239,68,68,0.5))" }} />
                          <div className="flex items-center gap-3">
                            <span className="material-symbols-outlined text-base" style={{ color: "rgba(239,68,68,0.75)" }}>warning</span>
                            <span className="text-base font-black tracking-[0.25em] uppercase" style={{ color: "rgba(255,255,255,0.75)" }}>비교</span>
                            <span className="material-symbols-outlined text-base" style={{ color: "rgba(14,165,165,0.75)" }}>shield</span>
                          </div>
                          <div className="flex-1 h-px" style={{ background: "linear-gradient(to left, transparent, rgba(14,165,165,0.5))" }} />
                        </div>

                        {/* ⑤ BEFORE / AFTER */}
                        <div className="grid grid-cols-2">

                          {/* BEFORE */}
                          <div style={{ borderRight: "1px solid rgba(255,255,255,0.07)" }}>
                            <div className="flex items-center gap-2.5 px-6 py-3.5"
                              style={{ background: "rgba(239,68,68,0.13)", borderBottom: "1px solid rgba(239,68,68,0.2)" }}>
                              <span className="material-symbols-outlined text-lg text-error" style={{ fontVariationSettings: "'FILL' 1" }}>warning</span>
                              <span className="text-sm font-black text-error tracking-wide">BEFORE · 방어 전 응답</span>
                            </div>
                            <div className="p-6 space-y-4">
                              {r.danger_highlight && (
                                <div className="rounded-xl p-4 danger-pulse"
                                  style={{ background: "rgba(239,68,68,0.09)", border: "1.5px solid rgba(239,68,68,0.3)" }}>
                                  <p className="text-[11px] font-black text-error uppercase tracking-widest mb-2.5">⚠ 핵심 위협 내용</p>
                                  <pre className="font-mono text-sm font-semibold text-error/90 leading-relaxed whitespace-pre-wrap break-words overflow-y-auto" style={{ maxHeight: "160px" }}>
                                    {r.danger_highlight}
                                  </pre>
                                </div>
                              )}
                              <div>
                                <p className="text-[10px] font-bold uppercase tracking-widest text-white/20 mb-1.5">AI 응답 전문</p>
                                <p className="font-mono text-xs text-white/40 leading-relaxed whitespace-pre-wrap break-words line-clamp-5">
                                  {r.target_response}
                                </p>
                              </div>
                            </div>
                          </div>

                          {/* AFTER */}
                          <div>
                            <div className="flex items-center gap-2.5 px-6 py-3.5"
                              style={{ background: "rgba(14,165,165,0.13)", borderBottom: "1px solid rgba(14,165,165,0.2)" }}>
                              <span className="material-symbols-outlined text-lg text-primary" style={{ fontVariationSettings: "'FILL' 1" }}>shield</span>
                              <span className="text-sm font-black text-primary tracking-wide">AFTER · 방어 후 응답</span>
                            </div>
                            <div className="p-6">
                              {r.defense_code ? (
                                <div className="rounded-xl p-4 safe-pulse"
                                  style={{ background: "rgba(14,165,165,0.09)", border: "1.5px solid rgba(14,165,165,0.3)" }}>
                                  <p className="text-[11px] font-black text-primary uppercase tracking-widest mb-2.5">✓ 방어 결과</p>
                                  <p className="text-xs leading-relaxed whitespace-pre-wrap break-words overflow-y-auto"
                                    style={{ color: "#5eead4cc", maxHeight: "160px" }}>
                                    {r.defense_code}
                                  </p>
                                </div>
                              ) : (
                                <p className="text-xs text-white/20 italic">방어 응답 미생성</p>
                              )}
                            </div>
                          </div>

                        </div>
                      </div>
                    )}

                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
