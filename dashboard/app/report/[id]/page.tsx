"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import DashboardLayout from "../../../components/DashboardLayout";
import { getScanStatus, getScanResults, ScanResult } from "../../../lib/api";
import { MOCK_SCAN_STATUS, MOCK_SCAN_RESULTS } from "../../../lib/mockClientData";

const SEVERITY_CFG = {
  critical: { label: "긴급", color: "#ef4444", bg: "rgba(239,68,68,0.12)", border: "rgba(239,68,68,0.3)" },
  high:     { label: "높음", color: "#f97316", bg: "rgba(249,115,22,0.12)", border: "rgba(249,115,22,0.3)" },
  medium:   { label: "중간", color: "#eab308", bg: "rgba(234,179,8,0.10)",  border: "rgba(234,179,8,0.25)" },
  low:      { label: "낮음", color: "#22c55e", bg: "rgba(34,197,94,0.10)",  border: "rgba(34,197,94,0.2)" },
} as const;

const CATEGORY_META: Record<string, { name: string; color: string; icon: string }> = {
  LLM01: { name: "Prompt Injection",       color: "#ef4444", icon: "terminal"             },
  LLM02: { name: "Sensitive Info Leakage", color: "#0ea5a5", icon: "data_loss_prevention" },
  LLM06: { name: "Excessive Agency",       color: "#a78bfa", icon: "psychology"            },
  LLM07: { name: "System Prompt Leakage",  color: "#3ec8c8", icon: "lock_open"             },
};

const PHASE_META: Record<number, { label: string; short: string; color: string; icon: string }> = {
  1: { label: "Phase 1 · DB 스캔",    short: "P1", color: "#ef4444", icon: "database"      },
  2: { label: "Phase 2 · Red Agent",  short: "P2", color: "#0ea5a5", icon: "psychology"    },
  3: { label: "Phase 3 · Blue Agent", short: "P3", color: "#a78bfa", icon: "shield"        },
  4: { label: "Phase 4 · 검증",       short: "P4", color: "#3ec8c8", icon: "verified_user" },
};

function fmtElapsed(s: number) {
  return `${Math.floor(s / 60)}분 ${s % 60}초`;
}

function SectionTitle({ icon, label, sub }: { icon: string; label: string; sub?: string }) {
  return (
    <div className="flex items-end justify-between mb-5">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-xl bg-primary/10 flex items-center justify-center">
          <span className="material-symbols-outlined text-primary text-base" style={{ fontVariationSettings: "'FILL' 1" }}>
            {icon}
          </span>
        </div>
        <h2 className="text-lg font-extrabold text-white font-headline tracking-tight">{label}</h2>
      </div>
      {sub && <span className="text-[10px] font-bold text-on-surface-variant/40 uppercase tracking-widest">{sub}</span>}
    </div>
  );
}

export default function ReportPage({ params }: { params: { id: string } }) {
  const router = useRouter();
  const sessionId = params.id;

  const [status, setStatus] = useState<typeof MOCK_SCAN_STATUS | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const [s, r] = await Promise.all([
          getScanStatus(sessionId).catch(() => ({ ...MOCK_SCAN_STATUS, session_id: sessionId })),
          getScanResults(sessionId).catch(() =>
            MOCK_SCAN_RESULTS.map((x) => ({ ...x, session_id: sessionId }))
          ),
        ]);
        setStatus(s as typeof MOCK_SCAN_STATUS);
        setResults(r);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [sessionId]);

  const total      = results.length;
  const vulnerable = results.filter((r) => r.judgment === "vulnerable");
  const safe       = results.filter((r) => r.judgment === "safe");
  const vulnRate   = total > 0 ? Math.round((vulnerable.length / total) * 100) : 0;
  const defCnt     = results.filter((r) => r.defense_code).length;
  const blkCnt     = results.filter((r) => r.verify_result === "blocked").length;

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  const phCounts: Record<number, { total: number; vuln: number }> = {};
  results.forEach((r) => {
    if (r.judgment === "vulnerable" && r.severity in sevCounts) sevCounts[r.severity]++;
    if (!phCounts[r.phase]) phCounts[r.phase] = { total: 0, vuln: 0 };
    phCounts[r.phase].total++;
    if (r.judgment === "vulnerable") phCounts[r.phase].vuln++;
  });

  const comparisons = vulnerable.filter((r) => r.attack_prompt && r.target_response);

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
      <div className="p-10 max-w-[1700px] mx-auto w-full space-y-10 page-fade-in">

        {/* ── 헤더 ── */}
        <div className="flex items-start justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest">
              <span className="material-symbols-outlined text-xs">assessment</span>
              SECURITY REPORT
            </div>
            <h1 className="text-4xl font-extrabold tracking-tight font-headline text-white">
              스캔 결과 보고서
            </h1>
            <div className="flex items-center gap-4 text-xs text-on-surface-variant/50 font-mono pt-0.5">
              <span>SESSION · {sessionId.toUpperCase().slice(0, 16)}</span>
              <span>· 총 {total}건 테스트</span>
              {status?.elapsed_seconds ? <span>· 소요 {fmtElapsed(status.elapsed_seconds)}</span> : null}
            </div>
          </div>
          <button
            onClick={() => router.push(`/scan/${sessionId}`)}
            className="flex items-center gap-2 px-5 py-3 rounded-2xl bg-white/5 border border-white/10 text-on-surface-variant hover:text-white hover:border-primary/30 transition-all font-medium text-sm shrink-0"
          >
            <span className="material-symbols-outlined text-lg">arrow_back</span>
            스캔으로 돌아가기
          </button>
        </div>

        {/* ════════════════════════════════════════
            SECTION 1 — 핵심 지표
        ════════════════════════════════════════ */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: "총 테스트",  value: total,             icon: "labs",          color: "#0ea5a5", bg: "rgba(14,165,165,0.08)",   border: "rgba(14,165,165,0.2)" },
            { label: "취약 탐지",  value: vulnerable.length,  icon: "gpp_bad",       color: "#ef4444", bg: "rgba(239,68,68,0.08)",   border: "rgba(239,68,68,0.2)",  pulse: vulnerable.length > 0 },
            { label: "방어 생성",  value: defCnt,             icon: "shield",        color: "#a78bfa", bg: "rgba(167,139,250,0.08)", border: "rgba(167,139,250,0.2)" },
            { label: "차단 확인",  value: blkCnt,             icon: "verified_user", color: "#34d399", bg: "rgba(52,211,153,0.08)",  border: "rgba(52,211,153,0.2)" },
          ].map((c) => (
            <div key={c.label} className="relative rounded-2xl p-6 overflow-hidden transition-all hover:scale-[1.01]"
              style={{ background: c.bg, border: `1px solid ${c.border}` }}>
              <div className="absolute -right-3 -bottom-3 opacity-[0.07]">
                <span className="material-symbols-outlined" style={{ fontSize: 72, color: c.color }}>{c.icon}</span>
              </div>
              <div className="absolute top-0 left-0 right-0 h-[2px]"
                style={{ background: `linear-gradient(to right, ${c.color}, ${c.color}44)` }} />
              <div className="relative">
                <p className="text-[10px] font-black tracking-widest uppercase mb-2" style={{ color: `${c.color}bb` }}>{c.label}</p>
                <p className="text-4xl font-black tracking-tighter" style={{
                  color: c.pulse ? c.color : "#fff",
                  textShadow: c.pulse ? `0 0 24px ${c.color}88` : "none",
                }}>{c.value}</p>
              </div>
            </div>
          ))}
        </div>

        {/* ════════════════════════════════════════
            SECTION 2 — 분포 차트 2열
        ════════════════════════════════════════ */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* 취약률 도넛 */}
          <div className="glass-panel rounded-2xl p-7">
            <SectionTitle icon="donut_large" label="취약률 분포" />
            <div className="flex items-center gap-10">
              <div className="relative w-36 h-36 shrink-0">
                <div className="w-full h-full rounded-full" style={{
                  background: total === 0
                    ? "rgba(255,255,255,0.05)"
                    : `conic-gradient(#ef4444 0% ${vulnRate}%, #22c55e ${vulnRate}% 100%)`,
                  boxShadow: vulnerable.length > 0 ? "0 0 28px rgba(239,68,68,0.22)" : "none",
                }} />
                <div className="absolute inset-[14px] rounded-full flex flex-col items-center justify-center"
                  style={{ background: "#071824" }}>
                  <span className="text-2xl font-black text-white">{vulnRate}%</span>
                  <span className="text-[9px] text-on-surface-variant/50 font-bold uppercase tracking-widest">취약률</span>
                </div>
              </div>
              <div className="flex-1 space-y-5">
                {[
                  { label: "취약", count: vulnerable.length, color: "#ef4444", rate: vulnRate },
                  { label: "안전", count: safe.length,       color: "#22c55e", rate: 100 - vulnRate },
                ].map((item) => (
                  <div key={item.label} className="flex items-center gap-3">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0"
                      style={{ background: item.color, boxShadow: `0 0 6px ${item.color}` }} />
                    <div className="flex-1">
                      <div className="flex justify-between text-xs font-bold mb-1.5">
                        <span style={{ color: item.color }}>{item.label}</span>
                        <span className="text-white font-mono">{item.count}건</span>
                      </div>
                      <div className="h-2 bg-white/[0.05] rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-1000"
                          style={{ width: `${item.rate}%`, background: item.color }} />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* 심각도 분포 */}
          <div className="glass-panel rounded-2xl p-7">
            <SectionTitle icon="warning" label="심각도 분포" sub={`취약 ${vulnerable.length}건 기준`} />
            <div className="space-y-3.5">
              {(["critical", "high", "medium", "low"] as const).map((sev) => {
                const cfg = SEVERITY_CFG[sev];
                const cnt = sevCounts[sev];
                const pct = vulnerable.length > 0 ? Math.round((cnt / vulnerable.length) * 100) : 0;
                return (
                  <div key={sev} className="flex items-center gap-4">
                    <span className="w-12 text-[10px] font-black uppercase tracking-wide shrink-0" style={{ color: cfg.color }}>
                      {cfg.label}
                    </span>
                    <div className="flex-1 h-7 rounded-lg overflow-hidden relative"
                      style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.05)" }}>
                      {cnt > 0 ? (
                        <div className="h-full rounded-lg flex items-center justify-end pr-3 transition-all duration-1000"
                          style={{
                            width: `${Math.max(pct, 10)}%`,
                            background: `linear-gradient(to right, ${cfg.bg.replace("0.12","0.3")}, ${cfg.bg})`,
                            borderRight: `2px solid ${cfg.border}`,
                          }}>
                          <span className="text-[11px] font-black" style={{ color: cfg.color }}>{cnt}</span>
                        </div>
                      ) : (
                        <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-on-surface-variant/20 font-bold">0</span>
                      )}
                    </div>
                    <span className="w-8 text-right text-[10px] font-mono text-on-surface-variant/40 shrink-0">{pct}%</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ════════════════════════════════════════
            SECTION 3 — 카테고리 + Phase 2열
        ════════════════════════════════════════ */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* 공격 카테고리 */}
          <div className="glass-panel rounded-2xl p-7">
            <SectionTitle icon="security" label="공격 카테고리별 취약 현황" />
            <div className="space-y-3">
              {Object.entries(CATEGORY_META).map(([cat, meta]) => {
                const vulnN  = results.filter((r) => r.category === cat && r.judgment === "vulnerable").length;
                const totalN = results.filter((r) => r.category === cat).length;
                const pct    = totalN > 0 ? Math.round((vulnN / totalN) * 100) : 0;
                return (
                  <div key={cat} className="rounded-xl p-4 border border-white/[0.05] space-y-2"
                    style={{ background: "rgba(255,255,255,0.02)" }}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                          style={{ background: `${meta.color}18`, border: `1px solid ${meta.color}30` }}>
                          <span className="material-symbols-outlined text-sm" style={{ color: meta.color }}>{meta.icon}</span>
                        </div>
                        <div>
                          <span className="text-[10px] font-black uppercase tracking-widest" style={{ color: meta.color }}>{cat}</span>
                          <p className="text-[11px] text-on-surface-variant/50">{meta.name}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <span className="text-xl font-black"
                          style={{ color: vulnN > 0 ? meta.color : "rgba(255,255,255,0.15)" }}>{vulnN}</span>
                        <span className="text-[10px] text-on-surface-variant/30 ml-0.5">/{totalN}</span>
                      </div>
                    </div>
                    <div className="h-1.5 bg-white/[0.04] rounded-full overflow-hidden">
                      <div className="h-full rounded-full transition-all duration-1000"
                        style={{ width: `${pct}%`, background: `linear-gradient(to right, ${meta.color}55, ${meta.color})` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Phase별 */}
          <div className="glass-panel rounded-2xl p-7">
            <SectionTitle icon="layers" label="Phase별 탐지 현황" />
            <div className="space-y-3">
              {[1, 2, 3, 4].map((ph) => {
                const meta = PHASE_META[ph];
                const pc   = phCounts[ph] || { total: 0, vuln: 0 };
                const pct  = pc.total > 0 ? Math.round((pc.vuln / pc.total) * 100) : 0;
                return (
                  <div key={ph} className="flex items-center gap-4 p-4 rounded-xl border border-white/[0.05]"
                    style={{ background: "rgba(255,255,255,0.02)" }}>
                    <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
                      style={{ background: `${meta.color}18`, border: `1px solid ${meta.color}30` }}>
                      <span className="material-symbols-outlined text-sm" style={{ color: meta.color }}>{meta.icon}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex justify-between text-xs mb-2">
                        <span className="font-bold text-on-surface/80">{meta.label}</span>
                        <span className="font-mono text-[10px] font-bold"
                          style={{ color: pc.vuln > 0 ? "#ef4444" : "#22c55e" }}>
                          {pc.vuln > 0 ? `취약 ${pc.vuln}건` : pc.total > 0 ? "전체 안전" : "—"}
                        </span>
                      </div>
                      <div className="flex h-2 rounded-full overflow-hidden">
                        {pc.total > 0 ? (
                          <>
                            {pc.vuln > 0 && (
                              <div className="transition-all duration-1000"
                                style={{ width: `${pct}%`, background: "#ef4444", borderRadius: "9999px 0 0 9999px", minWidth: 4 }} />
                            )}
                            <div className="flex-1 transition-all duration-1000"
                              style={{ background: "#22c55e44", borderRadius: pc.vuln === 0 ? "9999px" : "0 9999px 9999px 0" }} />
                          </>
                        ) : (
                          <div className="w-full rounded-full bg-white/5" />
                        )}
                      </div>
                      <p className="text-[9px] text-on-surface-variant/30 font-mono mt-1.5">{pc.total}건 테스트</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ════════════════════════════════════════
            SECTION 4 — 전체 테스트 결과 테이블
        ════════════════════════════════════════ */}
        <div>
          <SectionTitle icon="table_rows" label="전체 테스트 결과" sub={`${results.length}건`} />
          <div className="glass-panel rounded-2xl overflow-hidden">
            {/* 테이블 헤더 */}
            <div className="grid px-6 py-3.5 border-b border-white/[0.06] bg-white/[0.02]"
              style={{ gridTemplateColumns: "52px 68px 76px 96px 1fr 100px" }}>
              {["#", "Phase", "카테고리", "심각도", "공격 프롬프트", "판정"].map((h, i) => (
                <span key={h}
                  className={`text-[10px] font-black tracking-widest uppercase text-on-surface-variant/40 ${i === 5 ? "text-center" : ""}`}>
                  {h}
                </span>
              ))}
            </div>
            {/* 테이블 바디 */}
            <div className="divide-y divide-white/[0.03]">
              {results.length === 0 ? (
                <div className="py-16 text-center text-sm text-on-surface-variant/40">결과 없음</div>
              ) : results.map((r, i) => {
                const sev     = SEVERITY_CFG[r.severity as keyof typeof SEVERITY_CFG] ?? SEVERITY_CFG.medium;
                const isVuln  = r.judgment === "vulnerable";
                const phMeta  = PHASE_META[r.phase];
                const catMeta = CATEGORY_META[r.category];
                return (
                  <div key={r.id} className="grid px-6 py-3.5 items-center group hover:bg-white/[0.02] transition-colors"
                    style={{ gridTemplateColumns: "52px 68px 76px 96px 1fr 100px" }}>
                    <span className="font-mono text-[10px] text-primary/50">#{String(i + 1).padStart(3, "0")}</span>
                    <span className="text-[10px] font-black uppercase tracking-wide"
                      style={{ color: phMeta?.color ?? "#8aa8b8" }}>{phMeta?.short ?? `P${r.phase}`}</span>
                    <div className="flex items-center gap-1.5">
                      {catMeta && <span className="material-symbols-outlined text-sm" style={{ color: catMeta.color }}>{catMeta.icon}</span>}
                      <span className="text-[10px] font-black" style={{ color: catMeta?.color ?? "#8aa8b8" }}>{r.category}</span>
                    </div>
                    <div>
                      <span className="text-[10px] font-black px-2.5 py-1 rounded-lg border"
                        style={{ color: sev.color, background: sev.bg, borderColor: sev.border }}>
                        {sev.label}
                      </span>
                    </div>
                    <div className="pr-4 min-w-0">
                      <p className="text-xs font-mono text-on-surface/70 truncate group-hover:text-white transition-colors">
                        {r.attack_prompt}
                      </p>
                      {r.defense_code && (
                        <p className="text-[9px] text-blue-400/50 mt-0.5">🛡 방어코드 생성됨</p>
                      )}
                    </div>
                    <div className="flex justify-center">
                      <span className={`text-[10px] font-black px-3 py-1 rounded-full border ${
                        isVuln ? "text-error border-error/30 bg-error/10" : "text-tertiary border-tertiary/30 bg-tertiary/10"
                      }`}>
                        {isVuln ? "취약" : "안전"}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ════════════════════════════════════════
            SECTION 5 — 공격-방어 비교
        ════════════════════════════════════════ */}
        {comparisons.length > 0 && (
          <div>
            <SectionTitle icon="compare_arrows" label="공격-방어 비교" sub={`취약 ${comparisons.length}건`} />

            {/* 컬럼 레이블 헤더 */}
            <div className="hidden lg:grid grid-cols-3 gap-4 mb-3 px-1">
              {[
                { emoji: "🗡", label: "공격 프롬프트",  color: "rgba(239,68,68,0.7)"   },
                { emoji: "💬", label: "챗봇 응답 (방어 전)", color: "rgba(14,165,165,0.7)" },
                { emoji: "🛡", label: "방어 코드",      color: "rgba(96,165,250,0.7)"  },
              ].map((col) => (
                <div key={col.label} className="flex items-center gap-2 px-4">
                  <span className="text-sm">{col.emoji}</span>
                  <span className="text-[10px] font-black uppercase tracking-widest" style={{ color: col.color }}>
                    {col.label}
                  </span>
                </div>
              ))}
            </div>

            <div className="space-y-4">
              {comparisons.map((r, i) => {
                const sev       = SEVERITY_CFG[r.severity as keyof typeof SEVERITY_CFG] ?? SEVERITY_CFG.medium;
                const catMeta   = CATEGORY_META[r.category];
                const isBlocked = r.verify_result === "blocked";
                const hasDef    = !!r.defense_code;
                const hasVerify = !!r.verify_result;

                return (
                  <div key={r.id} className="glass-panel rounded-2xl overflow-hidden">
                    {/* 카드 상단 배지 줄 */}
                    <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 border-b border-white/[0.05]"
                      style={{ background: "rgba(255,255,255,0.02)" }}>
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="font-mono text-[10px] text-primary/50">#{String(i + 1).padStart(3, "0")}</span>
                        <span className="text-[10px] font-black px-2.5 py-0.5 rounded-lg border"
                          style={{ color: sev.color, background: sev.bg, borderColor: sev.border }}>
                          {sev.label}
                        </span>
                        {catMeta && (
                          <div className="flex items-center gap-1.5">
                            <span className="material-symbols-outlined text-sm" style={{ color: catMeta.color }}>{catMeta.icon}</span>
                            <span className="text-[10px] font-black" style={{ color: catMeta.color }}>
                              {r.category} · {catMeta.name}
                            </span>
                          </div>
                        )}
                        <span className="text-[10px] text-on-surface-variant/40">Phase {r.phase}</span>
                      </div>
                      {hasVerify && (
                        <span className={`text-[10px] font-black px-3 py-1 rounded-full border ${
                          isBlocked
                            ? "text-tertiary border-tertiary/30 bg-tertiary/10"
                            : "text-error border-error/30 bg-error/10"
                        }`}>
                          {isBlocked ? "✓ 방어 차단 성공" : "⚠ 우회됨"}
                        </span>
                      )}
                    </div>

                    {/* 3열 본문 */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 divide-y lg:divide-y-0 lg:divide-x divide-white/[0.05]">
                      {/* 공격 */}
                      <div className="p-5">
                        <div className="flex items-center gap-2 mb-3 lg:hidden">
                          <span className="text-sm">🗡</span>
                          <span className="text-[10px] font-black text-error/70 uppercase tracking-widest">공격 프롬프트</span>
                        </div>
                        <div className="p-4 rounded-xl text-xs font-mono text-on-surface/80 leading-relaxed break-words whitespace-pre-wrap"
                          style={{ background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.14)" }}>
                          {r.attack_prompt}
                        </div>
                      </div>

                      {/* 응답 */}
                      <div className="p-5">
                        <div className="flex items-center gap-2 mb-3 lg:hidden">
                          <span className="text-sm">💬</span>
                          <span className="text-[10px] font-black text-primary/70 uppercase tracking-widest">챗봇 응답</span>
                        </div>
                        <div className="p-4 rounded-xl text-xs font-mono text-on-surface-variant/80 leading-relaxed break-words whitespace-pre-wrap"
                          style={{ background: "rgba(14,165,165,0.05)", border: "1px solid rgba(14,165,165,0.12)" }}>
                          {r.target_response || "— 응답 없음 —"}
                        </div>
                      </div>

                      {/* 방어 코드 */}
                      <div className="p-5">
                        <div className="flex items-center gap-2 mb-3 lg:hidden">
                          <span className="text-sm">🛡</span>
                          <span className="text-[10px] font-black text-blue-400/70 uppercase tracking-widest">방어 코드</span>
                        </div>
                        {hasDef ? (
                          <pre className="p-4 rounded-xl text-[10px] font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap break-words max-h-40"
                            style={{ background: "rgba(0,0,0,0.35)", border: "1px solid rgba(96,165,250,0.15)", color: "#93c5fd" }}>
                            {r.defense_code}
                          </pre>
                        ) : (
                          <div className="p-4 rounded-xl flex items-center gap-2"
                            style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)" }}>
                            <span className="material-symbols-outlined text-sm text-on-surface-variant/30">info</span>
                            <p className="text-[10px] text-on-surface-variant/30">방어 코드 미생성</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

      </div>
    </DashboardLayout>
  );
}
