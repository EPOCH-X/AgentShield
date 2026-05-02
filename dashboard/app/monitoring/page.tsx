"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import DashboardLayout from "../../components/DashboardLayout";
import {
  getMonitoringDashboard,
  getViolations,
  Violation,
} from "../../lib/api";
import { MOCK_DASHBOARD, MOCK_VIOLATIONS } from "../../lib/mockClientData";

function visiblePageNumbers(current: number, total: number, max = 5): number[] {
  if (total <= 0) return [];
  if (total <= max) return Array.from({ length: total }, (_, i) => i + 1);
  const half = Math.floor(max / 2);
  let start = current - half;
  if (start < 1) start = 1;
  let end = start + max - 1;
  if (end > total) {
    end = total;
    start = Math.max(1, end - max + 1);
  }
  return Array.from({ length: end - start + 1 }, (_, i) => start + i);
}

// severity별 색상 — high를 orange로 분리
const SEVERITY_CONFIG: Record<string, {
  label: string;
  bg: string;
  text: string;
  border: string;
  dot: string;
  rowGlow: string;
}> = {
  critical: {
    label: "긴급",
    bg: "rgba(239,68,68,0.1)",
    text: "#ef4444",
    border: "rgba(239,68,68,0.3)",
    dot: "#ef4444",
    rowGlow: "border-l-2 border-l-red-500/60",
  },
  high: {
    label: "높음",
    bg: "rgba(249,115,22,0.1)",
    text: "#f97316",
    border: "rgba(249,115,22,0.3)",
    dot: "#f97316",
    rowGlow: "border-l-2 border-l-orange-500/40",
  },
  medium: {
    label: "중간",
    bg: "rgba(234,179,8,0.08)",
    text: "#eab308",
    border: "rgba(234,179,8,0.25)",
    dot: "#eab308",
    rowGlow: "",
  },
  low: {
    label: "낮음",
    bg: "rgba(34,197,94,0.08)",
    text: "#22c55e",
    border: "rgba(34,197,94,0.2)",
    dot: "#22c55e",
    rowGlow: "",
  },
};

const VIOLATION_ICON: Record<string, string> = {
  P1_leak: "data_loss_prevention",
  P2_misuse: "terminal",
  P3_ratelimit: "speed",
  default: "security",
};

const SANCTION_META: Record<string, { label: string; color: string }> = {
  blocked: { label: "세션 차단됨", color: "#ef4444" },
  warned: { label: "경고 발송됨", color: "#f97316" },
  logged: { label: "관리자 알림", color: "#8aa8b8" },
  masked: { label: "마스킹 처리됨", color: "#0ea5a5" },
};

const AVATAR_COLORS = ["#0ea5a5", "#a78bfa", "#f97316", "#22c55e", "#ef4444", "#60a5fa"];

function avatarColor(id: string | number) {
  const n = typeof id === "number" ? id : id.charCodeAt(0);
  return AVATAR_COLORS[n % AVATAR_COLORS.length];
}

// 홀수=남성(파랑), 짝수=여성(핑크)
function genderColors(id: string | number): { bg: string; border: string; icon: string } {
  const n = typeof id === "number" ? id : parseInt(id.replace(/\D/g, "") || "1", 10);
  return n % 2 === 1
    ? { bg: "rgba(96,165,250,0.18)", border: "rgba(96,165,250,0.45)", icon: "#93c5fd" }
    : { bg: "rgba(244,114,182,0.18)", border: "rgba(244,114,182,0.45)", icon: "#f9a8d4" };
}

export default function MonitoringPage() {
  const [dashboard, setDashboard] = useState<{
    daily_requests: number;
    violations_count: number;
    blocked_count: number;
    active_employees: number;
    total_employees: number;
  } | null>(null);
  const [violations, setViolations] = useState<Violation[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [deptFilter, setDeptFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [selectedViolation, setSelectedViolation] = useState<Violation | null>(null);
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 10;

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setLoadError(false);
    try {
      const [dash, viols] = await Promise.all([getMonitoringDashboard(), getViolations()]);
      setDashboard(dash);
      setViolations(viols);
    } catch {
      setDashboard(MOCK_DASHBOARD);
      setViolations(MOCK_VIOLATIONS);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDashboard(); }, [loadDashboard]);

  async function applyFilters() {
    try {
      const viols = await getViolations({
        department: deptFilter || undefined,
        violation_type: typeFilter || undefined,
      });
      setViolations(viols);
      setPage(1);
    } catch {
      let filtered = [...MOCK_VIOLATIONS];
      if (deptFilter) filtered = filtered.filter((v) => v.department === deptFilter);
      if (typeFilter) filtered = filtered.filter((v) => v.violation_type === typeFilter);
      setViolations(filtered);
      setPage(1);
    }
  }

  function resetFilters() {
    setDeptFilter("");
    setTypeFilter("");
    getViolations()
      .then((v) => setViolations(v))
      .catch(() => setViolations(MOCK_VIOLATIONS));
    setPage(1);
  }

  const paged = violations.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.ceil(violations.length / PAGE_SIZE);
  const criticalCount = violations.filter((v) => v.severity === "critical").length;

  function formatDate(iso: string) {
    const d = new Date(iso);
    return {
      date: d.toLocaleDateString("ko-KR", { month: "2-digit", day: "2-digit" }),
      time: d.toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" }),
    };
  }

  const STAT_CARDS = [
    {
      icon: "bar_chart",
      label: "오늘 AI 요청",
      value: loading ? "—" : (dashboard?.daily_requests ?? 0).toLocaleString(),
      sub: "DAILY REQUESTS",
      accent: "#0ea5a5",
      accentBg: "rgba(14,165,165,0.08)",
    },
    {
      icon: "warning_amber",
      label: "총 위반 건수",
      value: loading ? "—" : (dashboard?.violations_count ?? 0).toLocaleString(),
      sub: "TOTAL VIOLATIONS",
      accent: "#f97316",
      accentBg: "rgba(249,115,22,0.08)",
    },
    {
      icon: "priority_high",
      label: "심각한 경고",
      value: loading ? "—" : criticalCount,
      sub: "ACTION REQUIRED",
      accent: "#ef4444",
      accentBg: criticalCount > 0 ? "rgba(239,68,68,0.1)" : "rgba(239,68,68,0.04)",
      pulse: criticalCount > 0,
    },
    {
      icon: "group",
      label: "모니터링 대상",
      value: loading ? "—" : (dashboard?.total_employees ?? 0).toLocaleString(),
      sub: `${dashboard?.active_employees ?? 0} ACTIVE`,
      accent: "#60a5fa",
      accentBg: "rgba(96,165,250,0.08)",
    },
    {
      icon: "block",
      label: "차단된 세션",
      value: loading ? "—" : (dashboard?.blocked_count ?? 0).toLocaleString(),
      sub: "BLOCKED TODAY",
      accent: "#ef4444",
      accentBg: "rgba(239,68,68,0.08)",
    },
  ];

  return (
    <DashboardLayout>
      <div className="p-10 space-y-8 max-w-[1700px] mx-auto w-full">

        {/* ─── 헤더 ─── */}
        <div className="flex items-end justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-[0.2em]">
              <span className="w-8 h-px bg-primary" />
              AI Usage Sentinel
            </div>
            <h2 className="text-4xl font-headline font-extrabold tracking-tight text-white">
              모니터링 및 위반
            </h2>
            <p className="text-on-surface-variant text-sm">
              직원 AI 사용 현황을 실시간으로 감시하고 정책 위반을 탐지합니다.
            </p>
            <p className="text-[11px] text-outline pt-0.5">
              정책 규칙 편집은{" "}
              <Link href="/monitoring/admin" className="text-primary/90 hover:text-primary font-bold underline-offset-2 hover:underline">
                관리자
              </Link>
              화면에서 할 수 있습니다.
            </p>
          </div>

          {/* 시스템 상태 */}
          <div
            className="px-5 py-3 rounded-2xl border backdrop-blur-sm"
            style={{
              background: "rgba(14,165,165,0.06)",
              borderColor: "rgba(14,165,165,0.2)",
            }}
          >
            <span className="text-[10px] block font-black text-on-surface-variant/50 tracking-widest uppercase mb-1">
              시스템 상태
            </span>
            <div className="flex items-center gap-2.5">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-tertiary opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-tertiary" />
              </span>
              <span className="text-sm font-black text-tertiary tracking-wide">ACTIVE SENTINEL</span>
            </div>
          </div>
        </div>

        {loadError && (
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-error/30 bg-error/10 px-5 py-4">
            <p className="text-sm text-error font-medium">데이터를 불러오지 못했습니다.</p>
            <button onClick={() => loadDashboard()} className="px-4 py-2 rounded-xl text-xs font-black uppercase bg-on-surface text-background hover:opacity-90">
              다시 시도
            </button>
          </div>
        )}

        {/* ─── 스탯 카드 ─── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
          {STAT_CARDS.map((card) => (
            <div
              key={card.label}
              className="relative rounded-2xl overflow-hidden transition-all hover:scale-[1.02]"
              style={{
                background: card.accentBg,
                border: `1px solid ${card.accent}22`,
                boxShadow: card.pulse ? `0 0 20px ${card.accent}33` : "none",
              }}
            >
              {/* 상단 액센트 라인 */}
              <div
                className="absolute top-0 left-0 right-0 h-[2px]"
                style={{ background: `linear-gradient(to right, ${card.accent}, ${card.accent}44)` }}
              />
              {/* 배경 아이콘 */}
              <div className="absolute -right-3 -bottom-3 opacity-[0.06]">
                <span className="material-symbols-outlined" style={{ fontSize: 80, color: card.accent }}>
                  {card.icon}
                </span>
              </div>

              <div className="relative p-5">
                <p className="text-[10px] font-black tracking-widest uppercase" style={{ color: `${card.accent}cc` }}>
                  {card.label}
                </p>
                <p
                  className="text-4xl font-black mt-2 tracking-tighter"
                  style={{
                    color: card.pulse ? card.accent : "#ffffff",
                    textShadow: card.pulse ? `0 0 20px ${card.accent}88` : "none",
                  }}
                >
                  {card.value}
                </p>
                <p className="text-[10px] font-bold uppercase tracking-wide mt-3 text-on-surface-variant/50">
                  {card.sub}
                </p>
              </div>
            </div>
          ))}
        </div>

        {/* ─── 필터 바 ─── */}
        <div
          className="p-4 rounded-2xl flex flex-wrap gap-4 items-end border"
          style={{
            background: "rgba(255,255,255,0.02)",
            borderColor: "rgba(255,255,255,0.06)",
          }}
        >
          <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              {
                label: "부서",
                value: deptFilter,
                setter: setDeptFilter,
                options: [
                  ["", "전체 부서"],
                  ["Engineering", "엔지니어링"],
                  ["Marketing", "마케팅"],
                  ["Finance", "재무"],
                  ["HR", "인사"],
                ],
              },
              {
                label: "위반 유형",
                value: typeFilter,
                setter: setTypeFilter,
                options: [
                  ["", "전체 유형"],
                  ["P1_leak", "데이터 유출"],
                  ["P2_misuse", "부적절한 프롬프트"],
                  ["P3_ratelimit", "속도 제한 초과"],
                ],
              },
            ].map((f) => (
              <div key={f.label} className="space-y-1.5">
                <label className="text-[10px] font-black text-on-surface-variant/40 tracking-widest uppercase ml-1">
                  {f.label}
                </label>
                <select
                  value={f.value}
                  onChange={(e) => f.setter(e.target.value)}
                  className="w-full bg-surface-container-lowest border border-white/10 rounded-xl text-xs px-3 py-2.5 text-on-surface focus:ring-1 focus:ring-primary/40 focus:outline-none"
                >
                  {f.options.map(([val, lbl]) => (
                    <option key={val} value={val}>{lbl}</option>
                  ))}
                </select>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={applyFilters}
              className="px-5 py-2.5 text-xs font-black tracking-widest text-on-primary bg-primary rounded-xl hover:bg-primary/80 transition-colors uppercase"
            >
              필터 적용
            </button>
            <button onClick={resetFilters} className="px-5 py-2.5 text-xs font-black tracking-widest text-outline hover:text-on-surface transition-colors uppercase">
              초기화
            </button>
          </div>
        </div>

        {/* ─── 위반 테이블 ─── */}
        <div
          className="rounded-2xl overflow-hidden shadow-2xl"
          style={{ border: "1px solid rgba(255,255,255,0.06)" }}
        >
          {/* 테이블 헤더 */}
          <div
            className="grid grid-cols-[80px_1fr_2fr_100px_140px_130px] px-6 py-4 border-b"
            style={{
              background: "rgba(255,255,255,0.03)",
              borderColor: "rgba(255,255,255,0.08)",
            }}
          >
            {["LOG ID", "직원", "위반 내용", "심각도", "조치", "시각"].map((h, i) => (
              <span
                key={h}
                className={`text-[10px] font-black tracking-widest uppercase text-on-surface-variant/40 ${i === 3 ? "text-center" : i === 5 ? "text-right" : ""}`}
              >
                {h}
              </span>
            ))}
          </div>

          {/* 테이블 바디 */}
          <div className="divide-y" style={{ divideColor: "rgba(255,255,255,0.04)" }}>
            {loading ? (
              <div className="py-20 flex flex-col items-center gap-4">
                <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-on-surface-variant">데이터 불러오는 중...</p>
              </div>
            ) : paged.length === 0 ? (
              <div className="py-20 text-center">
                <p className="text-sm text-on-surface-variant">위반 내역이 없습니다.</p>
              </div>
            ) : (
              paged.map((v) => {
                const sev = SEVERITY_CONFIG[v.severity] || SEVERITY_CONFIG.medium;
                const icon = VIOLATION_ICON[v.violation_type] || VIOLATION_ICON.default;
                const sanction = SANCTION_META[v.sanction] || { label: v.sanction, color: "#8aa8b8" };
                const dt = formatDate(v.created_at);
                const isCritical = v.severity === "critical";
                const gender = genderColors(v.id);

                return (
                  <div
                    key={v.id}
                    onClick={() => setSelectedViolation(v)}
                    className={`grid grid-cols-[80px_1fr_2fr_100px_140px_130px] px-6 py-4 items-center cursor-pointer group transition-all ${sev.rowGlow}`}
                    style={{
                      background: isCritical ? "rgba(239,68,68,0.03)" : "transparent",
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLDivElement).style.background = "rgba(14,165,165,0.04)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLDivElement).style.background = isCritical ? "rgba(239,68,68,0.03)" : "transparent";
                    }}
                  >
                    {/* LOG ID */}
                    <span className="font-mono text-xs font-bold" style={{ color: "#0ea5a5" }}>
                      #AS-{String(v.id).padStart(4, "0")}
                    </span>

                    {/* 직원 */}
                    <div className="flex items-center gap-3">
                      <div
                        className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
                        style={{ background: gender.bg, border: `1px solid ${gender.border}` }}
                      >
                        <span
                          className="material-symbols-outlined"
                          style={{ fontSize: 22, color: gender.icon, fontVariationSettings: "'FILL' 1" }}
                        >
                          person
                        </span>
                      </div>
                      <div>
                        <p className="text-sm font-bold text-white group-hover:text-primary transition-colors">
                          {v.employee_name || v.employee_id}
                        </p>
                        <p className="text-[10px] text-on-surface-variant/50 uppercase font-bold tracking-tight">
                          {v.department || "—"}
                        </p>
                      </div>
                    </div>

                    {/* 위반 내용 */}
                    <div className="flex items-center gap-2.5 pr-4">
                      <span
                        className="material-symbols-outlined text-base shrink-0 transition-colors"
                        style={{ color: sev.text }}
                      >
                        {icon}
                      </span>
                      <span className="text-sm text-on-surface/80 truncate">{v.description}</span>
                    </div>

                    {/* 심각도 배지 */}
                    <div className="flex justify-center">
                      <span
                        className="px-3 py-1 text-[10px] font-black rounded-lg uppercase tracking-widest"
                        style={{
                          background: sev.bg,
                          color: sev.text,
                          border: `1px solid ${sev.border}`,
                          boxShadow: isCritical ? `0 0 8px ${sev.dot}44` : "none",
                        }}
                      >
                        {sev.label}
                      </span>
                    </div>

                    {/* 조치 */}
                    <div className="flex items-center gap-2">
                      <span
                        className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{ background: sanction.color }}
                      />
                      <span className="text-xs font-bold uppercase tracking-tight" style={{ color: sanction.color }}>
                        {sanction.label}
                      </span>
                    </div>

                    {/* 시각 */}
                    <div className="text-right">
                      <p className="text-xs font-mono text-on-surface-variant/60">{dt.date}</p>
                      <p className="text-xs font-mono font-bold text-on-surface/70">{dt.time}</p>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* 페이지네이션 */}
          <div
            className="px-6 py-4 flex justify-between items-center border-t"
            style={{
              background: "rgba(255,255,255,0.02)",
              borderColor: "rgba(255,255,255,0.06)",
            }}
          >
            <p className="text-[11px] text-on-surface-variant/40 font-bold tracking-tight uppercase">
              {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, violations.length)} / {violations.length}건
            </p>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-2 rounded-lg hover:bg-white/5 text-on-surface-variant/40 transition-colors disabled:opacity-30"
              >
                <span className="material-symbols-outlined text-sm">chevron_left</span>
              </button>
              {visiblePageNumbers(page, totalPages, 5).map((p) => (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  className={`w-8 h-8 rounded-lg text-xs font-black transition-all ${
                    page === p
                      ? "bg-primary text-on-primary shadow-lg"
                      : "text-on-surface-variant/40 hover:bg-white/5 hover:text-on-surface"
                  }`}
                >
                  {p}
                </button>
              ))}
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages || totalPages === 0}
                className="p-2 rounded-lg hover:bg-white/5 text-on-surface-variant/40 transition-colors disabled:opacity-30"
              >
                <span className="material-symbols-outlined text-sm">chevron_right</span>
              </button>
            </div>
          </div>
        </div>

        {/* ─── 상세 드로어 ─── */}
        {selectedViolation && (() => {
          const sev = SEVERITY_CONFIG[selectedViolation.severity] || SEVERITY_CONFIG.medium;
          const sanction = SANCTION_META[selectedViolation.sanction] || { label: selectedViolation.sanction, color: "#8aa8b8" };
          const drawerGender = genderColors(selectedViolation.id);
          return (
            <div className="fixed inset-0 z-[60] flex" onClick={() => setSelectedViolation(null)}>
              <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" />
              <div
                className="fixed right-4 top-4 bottom-4 w-[460px] rounded-3xl z-[70] flex flex-col overflow-hidden"
                style={{
                  background: "rgba(7,24,36,0.97)",
                  border: `1px solid ${sev.border}`,
                  boxShadow: `0 0 60px rgba(0,0,0,0.8), 0 0 30px ${sev.dot}22`,
                }}
                onClick={(e) => e.stopPropagation()}
              >
                {/* 드로어 헤더 */}
                <div
                  className="p-6 flex items-center justify-between border-b"
                  style={{ borderColor: "rgba(255,255,255,0.06)" }}
                >
                  <div className="flex items-center gap-4">
                    <div
                      className="w-12 h-12 rounded-2xl flex items-center justify-center"
                      style={{ background: sev.bg, border: `1px solid ${sev.border}` }}
                    >
                      <span
                        className="material-symbols-outlined text-2xl"
                        style={{ color: sev.text, fontVariationSettings: "'FILL' 1" }}
                      >
                        gavel
                      </span>
                    </div>
                    <div>
                      <h3 className="text-lg font-black text-white">위반 상세 정보</h3>
                      <p className="text-[10px] font-mono tracking-widest uppercase mt-0.5" style={{ color: sev.text }}>
                        #AS-{String(selectedViolation.id).padStart(4, "0")}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedViolation(null)}
                    className="p-2.5 rounded-xl transition-all text-on-surface-variant/40 hover:text-white hover:bg-white/8"
                  >
                    <span className="material-symbols-outlined">close</span>
                  </button>
                </div>

                <div className="flex-1 overflow-y-auto p-6 space-y-6">
                  {/* 직원 */}
                  <div>
                    <p className="text-[10px] font-black text-on-surface-variant/40 tracking-widest uppercase mb-3">대상자</p>
                    <div
                      className="flex items-center gap-4 p-4 rounded-2xl"
                      style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" }}
                    >
                      <div
                        className="w-14 h-14 rounded-2xl flex items-center justify-center shrink-0"
                        style={{ background: drawerGender.bg, border: `2px solid ${drawerGender.border}` }}
                      >
                        <span
                          className="material-symbols-outlined"
                          style={{ fontSize: 32, color: drawerGender.icon, fontVariationSettings: "'FILL' 1" }}
                        >
                          person
                        </span>
                      </div>
                      <div>
                        <p className="text-lg font-black text-white">{selectedViolation.employee_name || selectedViolation.employee_id}</p>
                        <p className="text-xs font-bold uppercase tracking-tight text-on-surface-variant/50">{selectedViolation.department || "미지정"}</p>
                      </div>
                    </div>
                  </div>

                  {/* 위반 내용 */}
                  <div>
                    <p className="text-[10px] font-black text-on-surface-variant/40 tracking-widest uppercase mb-3">위반 내용</p>
                    <div
                      className="p-4 rounded-2xl space-y-2"
                      style={{
                        background: sev.bg,
                        borderLeft: `3px solid ${sev.text}`,
                        borderTop: `1px solid ${sev.border}`,
                        borderRight: `1px solid ${sev.border}`,
                        borderBottom: `1px solid ${sev.border}`,
                      }}
                    >
                      <p className="text-[10px] font-black uppercase tracking-widest" style={{ color: sev.text }}>
                        {selectedViolation.violation_type}
                      </p>
                      <p className="text-sm text-white/80 leading-relaxed">{selectedViolation.description}</p>
                    </div>
                  </div>

                  {/* 심각도 + 조치 */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-[10px] font-black text-on-surface-variant/40 tracking-widest uppercase mb-3">심각도</p>
                      <div
                        className="px-4 py-3 rounded-xl flex items-center gap-2"
                        style={{ background: sev.bg, border: `1px solid ${sev.border}` }}
                      >
                        <span className="w-2 h-2 rounded-full" style={{ background: sev.dot }} />
                        <span className="text-sm font-black" style={{ color: sev.text }}>{sev.label}</span>
                      </div>
                    </div>
                    <div>
                      <p className="text-[10px] font-black text-on-surface-variant/40 tracking-widest uppercase mb-3">조치</p>
                      <div
                        className="px-4 py-3 rounded-xl flex items-center gap-2"
                        style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)" }}
                      >
                        <span className="w-2 h-2 rounded-full" style={{ background: sanction.color }} />
                        <span className="text-sm font-bold" style={{ color: sanction.color }}>{sanction.label}</span>
                      </div>
                    </div>
                  </div>

                  {/* 해결 여부 */}
                  <div
                    className="flex items-center justify-between p-4 rounded-2xl"
                    style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)" }}
                  >
                    <span className="text-sm text-on-surface-variant/60">처리 상태</span>
                    <span
                      className="text-xs font-black uppercase tracking-wider px-3 py-1 rounded-full"
                      style={{
                        background: selectedViolation.resolved ? "rgba(34,197,94,0.1)" : "rgba(249,115,22,0.1)",
                        color: selectedViolation.resolved ? "#22c55e" : "#f97316",
                        border: `1px solid ${selectedViolation.resolved ? "rgba(34,197,94,0.2)" : "rgba(249,115,22,0.2)"}`,
                      }}
                    >
                      {selectedViolation.resolved ? "해결됨" : "처리 중"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          );
        })()}
      </div>
    </DashboardLayout>
  );
}
