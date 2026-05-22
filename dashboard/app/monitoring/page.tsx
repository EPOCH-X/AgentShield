"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import DashboardLayout from "../../components/DashboardLayout";
import MonitoringChatPanel from "../../components/MonitoringChatPanel";
import MonitoringPoliciesPanel from "../../components/MonitoringPoliciesPanel";
import MonitoringEmployeesPanel from "../../components/MonitoringEmployeesPanel";
import {
  getMonitoringDashboard,
  getViolations,
  getViolationContext,
  resolveViolation,
  Violation,
  ViolationContext,
} from "../../lib/api";

type MonitoringTab = "violations" | "policies" | "employees";

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

const SANCTION_META: Record<string, { label: string; color: string; icon: string }> = {
  blocked:        { label: "세션 차단됨",   color: "#ef4444", icon: "block" },
  rate_limited:   { label: "속도 제한 차단", color: "#f97316", icon: "speed" },
  masked:         { label: "마스킹 처리됨",  color: "#0ea5a5", icon: "visibility_off" },
  output_blocked: { label: "응답 차단됨",   color: "#a855f7", icon: "shield" },
  warned:         { label: "경고 발송됨",   color: "#f97316", icon: "warning" },
  logged:         { label: "관리자 알림",   color: "#8aa8b8", icon: "info" },
};

// violation_type → sanction 폴백. 과거 데이터(전부 sanction="blocked")도 다양하게 표시.
function deriveSanctionKey(v: Pick<Violation, "sanction" | "violation_type">): string {
  if (v.sanction && v.sanction !== "blocked") return v.sanction;
  switch (v.violation_type) {
    case "p1_confidential_scan":
    case "P1_leak":
      return "masked";
    case "p3_rate_limit":
    case "P3_ratelimit":
      return "rate_limited";
    case "p5_output_review":
      return "output_blocked";
    default:
      return v.sanction || "blocked";
  }
}

const VIOLATION_TYPE_LABEL: Record<string, string> = {
  p1_confidential_scan: "기밀 정보 유출",
  P1_leak:              "기밀 정보 유출",
  p2_inappropriate_use: "부적절 사용",
  P2_misuse:            "부적절 사용",
  p3_rate_limit:        "속도 제한 초과",
  P3_ratelimit:         "속도 제한 초과",
  p4_intent_review:     "악의 의도 탐지",
  p5_output_review:     "응답 정책 위반",
};

const VIOLATION_TABLE_COLUMNS = "90px 170px minmax(320px, 1fr) 90px 130px 100px";
const VIOLATION_TABLE_MIN_WIDTH = 900;

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
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedViolation, setSelectedViolation] = useState<Violation | null>(null);
  const [detailContext, setDetailContext] = useState<ViolationContext | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [resolveBusy, setResolveBusy] = useState(false);
  const [page, setPage] = useState(1);
  const [tab, setTab] = useState<MonitoringTab>("violations");
  const PAGE_SIZE = 10;

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setLoadError(false);
    try {
      const [dash, viols] = await Promise.all([getMonitoringDashboard(), getViolations()]);
      setDashboard(dash);
      setViolations(viols);
    } catch {
      setLoadError(true);
      setDashboard(null);
      setViolations([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDashboard(); }, [loadDashboard]);

  // 클라이언트 사이드 반응형 필터 — 셀렉트 변경 즉시 반영.
  const filtered = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    return violations.filter((v) => {
      if (deptFilter && v.department !== deptFilter) return false;
      if (typeFilter && v.violation_type !== typeFilter) return false;
      if (severityFilter && v.severity !== severityFilter) return false;
      if (statusFilter === "resolved" && !v.resolved) return false;
      if (statusFilter === "open" && v.resolved) return false;
      if (term) {
        const haystack = [
          v.description ?? "",
          v.employee_name ?? "",
          v.employee_id ?? "",
          v.department ?? "",
        ].join(" ").toLowerCase();
        if (!haystack.includes(term)) return false;
      }
      return true;
    });
  }, [violations, deptFilter, typeFilter, severityFilter, statusFilter, searchTerm]);

  // 필터 변경 시 1페이지로 점프
  useEffect(() => { setPage(1); }, [deptFilter, typeFilter, severityFilter, statusFilter, searchTerm]);

  function clearAllFilters() {
    setDeptFilter("");
    setTypeFilter("");
    setSeverityFilter("");
    setStatusFilter("");
    setSearchTerm("");
  }

  const hasActiveFilter = !!(deptFilter || typeFilter || severityFilter || statusFilter || searchTerm);

  const paged = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const actionRequiredCount = violations.filter((v) => v.severity === "critical" || v.severity === "high").length;

  // 상세 드로어 — 위반 선택 시 채팅 컨텍스트 로드
  useEffect(() => {
    if (!selectedViolation) {
      setDetailContext(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    setDetailContext(null);
    getViolationContext(selectedViolation.id)
      .then((ctx) => { if (!cancelled) setDetailContext(ctx); })
      .catch(() => { if (!cancelled) setDetailContext(null); })
      .finally(() => { if (!cancelled) setDetailLoading(false); });
    return () => { cancelled = true; };
  }, [selectedViolation]);

  async function handleResolve(id: number) {
    setResolveBusy(true);
    try {
      await resolveViolation(id);
      setViolations((prev) => prev.map((v) => v.id === id ? { ...v, resolved: true } : v));
      setSelectedViolation((prev) => prev && prev.id === id ? { ...prev, resolved: true } : prev);
    } catch {
      // noop — 사용자에게 별도 토스트 표시 안 함(기존 패턴 유지)
    } finally {
      setResolveBusy(false);
    }
  }

  function formatDate(iso: string) {
    const d = new Date(iso);
    return {
      date: d.toLocaleDateString("ko-KR", { month: "2-digit", day: "2-digit" }),
      time: d.toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      full: d.toLocaleString("ko-KR", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    };
  }

  function timeAgo(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1)  return "방금 전";
    if (m < 60) return `${m}분 전`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}시간 전`;
    const d = Math.floor(h / 24);
    if (d < 30) return `${d}일 전`;
    return `${Math.floor(d / 30)}달 전`;
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
      value: loading ? "—" : actionRequiredCount,
      sub: "ACTION REQUIRED",
      accent: "#ef4444",
      accentBg: actionRequiredCount > 0 ? "rgba(239,68,68,0.1)" : "rgba(239,68,68,0.04)",
      pulse: actionRequiredCount > 0,
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
      <div className="p-6 lg:p-10 max-w-[1820px] mx-auto w-full">
       <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-6">
        <div className="space-y-8 min-w-0">

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

        {/* ─── 탭 네비게이션 ─── */}
        <div className="flex items-center gap-1 border-b border-white/8">
          {[
            { id: "violations" as const, label: "위반 내역", icon: "report" },
            { id: "policies"   as const, label: "보안 정책 룰", icon: "policy" },
            { id: "employees"  as const, label: "직원 목록", icon: "groups" },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className="flex items-center gap-2 px-4 py-2.5 text-sm font-bold transition-all relative"
              style={{
                color: tab === t.id ? "var(--primary, #0ea5a5)" : "rgba(255,255,255,0.45)",
              }}
            >
              <span className="material-symbols-outlined text-base">{t.icon}</span>
              {t.label}
              {tab === t.id && (
                <span className="absolute left-0 right-0 -bottom-px h-0.5 bg-primary rounded-full" />
              )}
            </button>
          ))}
        </div>

        {/* ─── 탭: 정책 룰 ─── */}
        {tab === "policies" && <MonitoringPoliciesPanel />}

        {/* ─── 탭: 직원 목록 ─── */}
        {tab === "employees" && <MonitoringEmployeesPanel />}

        {/* ─── 탭: 위반 내역 (기본) ─── */}
        {tab === "violations" && (
        <>
        {/* ─── 필터 바 (반응형 — 셀렉트 변경 즉시 적용) ─── */}
        <div
          className="p-5 rounded-2xl border space-y-4"
          style={{
            background: "rgba(255,255,255,0.02)",
            borderColor: "rgba(255,255,255,0.06)",
          }}
        >
          {/* 상단: 검색 + 결과 카운트 + 초기화 */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[260px]">
              <span
                className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40"
                style={{ fontSize: 20 }}
              >
                search
              </span>
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="직원명 · 부서 · 위반 내용으로 검색"
                className="w-full bg-surface-container-lowest border border-white/10 rounded-xl text-sm pl-11 pr-4 py-3 text-on-surface placeholder:text-on-surface-variant/30 focus:ring-2 focus:ring-primary/40 focus:border-primary/40 focus:outline-none transition-all"
              />
            </div>
            <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-white/[0.02] border border-white/5">
              <span className="text-xs font-bold text-on-surface-variant/60">
                {hasActiveFilter ? "필터 적용됨" : "전체"}
              </span>
              <span className="text-sm font-black text-primary">{filtered.length.toLocaleString()}</span>
              <span className="text-xs text-on-surface-variant/40">/ {violations.length.toLocaleString()}건</span>
            </div>
            {hasActiveFilter && (
              <button
                onClick={clearAllFilters}
                className="flex items-center gap-1.5 px-4 py-3 text-xs font-bold rounded-xl text-on-surface-variant hover:text-white hover:bg-white/5 transition-colors"
              >
                <span className="material-symbols-outlined text-sm">refresh</span>
                초기화
              </button>
            )}
          </div>

          {/* 하단: 4개 셀렉트 — 변경 즉시 필터링 */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              {
                label: "부서",
                value: deptFilter,
                setter: setDeptFilter,
                icon: "domain",
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
                icon: "category",
                options: [
                  ["", "전체 유형"],
                  ["p1_confidential_scan", "기밀 정보 유출"],
                  ["p2_inappropriate_use", "부적절 사용"],
                  ["p3_rate_limit", "속도 제한 초과"],
                  ["p4_intent_review", "악의 의도 탐지"],
                  ["p5_output_review", "응답 정책 위반"],
                ],
              },
              {
                label: "심각도",
                value: severityFilter,
                setter: setSeverityFilter,
                icon: "priority_high",
                options: [
                  ["", "전체 심각도"],
                  ["critical", "긴급"],
                  ["high", "높음"],
                  ["medium", "중간"],
                  ["low", "낮음"],
                ],
              },
              {
                label: "처리 상태",
                value: statusFilter,
                setter: setStatusFilter,
                icon: "task_alt",
                options: [
                  ["", "전체 상태"],
                  ["open", "처리 중"],
                  ["resolved", "검토 완료"],
                ],
              },
            ].map((f) => (
              <div key={f.label} className="space-y-1.5">
                <label className="flex items-center gap-1.5 text-xs font-bold text-on-surface-variant/60 tracking-tight ml-1">
                  <span className="material-symbols-outlined" style={{ fontSize: 14 }}>{f.icon}</span>
                  {f.label}
                </label>
                <div className="relative">
                  <select
                    value={f.value}
                    onChange={(e) => f.setter(e.target.value)}
                    className={`w-full appearance-none bg-surface-container-lowest border rounded-xl text-sm px-4 py-3 pr-9 text-on-surface focus:ring-2 focus:ring-primary/40 focus:border-primary/40 focus:outline-none transition-all cursor-pointer ${
                      f.value ? "border-primary/40 bg-primary/5" : "border-white/10"
                    }`}
                  >
                    {f.options.map(([val, lbl]) => (
                      <option key={val} value={val}>{lbl}</option>
                    ))}
                  </select>
                  <span
                    className="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-on-surface-variant/50"
                    style={{ fontSize: 18 }}
                  >
                    expand_more
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ─── 위반 테이블 ─── */}
        <div
          className="rounded-2xl overflow-hidden shadow-2xl"
          style={{ border: "1px solid rgba(255,255,255,0.06)" }}
        >
          <div className="overflow-x-auto">
          {/* 테이블 헤더 */}
          <div
            className="grid px-6 py-4 border-b"
            style={{
              gridTemplateColumns: VIOLATION_TABLE_COLUMNS,
              minWidth: VIOLATION_TABLE_MIN_WIDTH,
              background: "rgba(255,255,255,0.03)",
              borderColor: "rgba(255,255,255,0.08)",
            }}
          >
            {["LOG ID", "직원", "위반 내용", "심각도", "조치", "발생 시각"].map((h, i) => (
              <span
                key={h}
                className={`text-xs font-black tracking-tight uppercase text-on-surface-variant/60 ${i === 3 ? "text-center" : i === 5 ? "text-right" : ""}`}
              >
                {h}
              </span>
            ))}
          </div>

          {/* 테이블 바디 */}
          <div className="divide-y divide-white/[0.04]">
            {loading ? (
              <div className="py-20 flex flex-col items-center gap-4" style={{ minWidth: VIOLATION_TABLE_MIN_WIDTH }}>
                <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-on-surface-variant">데이터 불러오는 중...</p>
              </div>
            ) : paged.length === 0 ? (
              <div className="py-20 flex flex-col items-center gap-3" style={{ minWidth: VIOLATION_TABLE_MIN_WIDTH }}>
                <span className="material-symbols-outlined text-on-surface-variant/40" style={{ fontSize: 48 }}>
                  {hasActiveFilter ? "filter_alt_off" : "shield_check"}
                </span>
                <p className="text-base font-bold text-on-surface-variant">
                  {hasActiveFilter ? "필터 조건에 맞는 위반 내역이 없습니다." : "위반 내역이 없습니다."}
                </p>
                {hasActiveFilter && (
                  <button
                    onClick={clearAllFilters}
                    className="text-xs font-bold text-primary hover:underline"
                  >
                    필터 초기화
                  </button>
                )}
              </div>
            ) : (
              paged.map((v) => {
                const sev = SEVERITY_CONFIG[v.severity] || SEVERITY_CONFIG.medium;
                const icon = VIOLATION_ICON[v.violation_type] || VIOLATION_ICON.default;
                const sanctionKey = deriveSanctionKey(v);
                const sanction = SANCTION_META[sanctionKey] || { label: sanctionKey, color: "#8aa8b8", icon: "info" };
                const dt = formatDate(v.created_at);
                const isCritical = v.severity === "critical";
                const gender = genderColors(v.id);

                return (
                  <div
                    key={v.id}
                    onClick={() => setSelectedViolation(v)}
                    className={`grid px-6 py-4 items-center cursor-pointer group transition-all ${sev.rowGlow}`}
                    style={{
                      gridTemplateColumns: VIOLATION_TABLE_COLUMNS,
                      minWidth: VIOLATION_TABLE_MIN_WIDTH,
                      background: isCritical ? "rgba(239,68,68,0.03)" : "transparent",
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLDivElement).style.background = "rgba(14,165,165,0.06)";
                      (e.currentTarget as HTMLDivElement).style.transform = "translateX(2px)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLDivElement).style.background = isCritical ? "rgba(239,68,68,0.03)" : "transparent";
                      (e.currentTarget as HTMLDivElement).style.transform = "translateX(0)";
                    }}
                  >
                    {/* LOG ID + 처리 상태 (완료=강조 / 대기=펄스) */}
                    <div className="flex flex-col gap-1.5">
                      <span className="font-mono text-sm font-black" style={{ color: "#0ea5a5" }}>
                        #AS-{String(v.id).padStart(4, "0")}
                      </span>
                      {v.resolved ? (
                        <span
                          className="inline-flex items-center gap-1 text-[10px] font-black px-1.5 py-0.5 rounded-md w-fit"
                          style={{
                            background: "rgba(34,197,94,0.15)",
                            color: "#22c55e",
                            border: "1px solid rgba(34,197,94,0.35)",
                          }}
                        >
                          <span className="material-symbols-outlined" style={{ fontSize: 12, fontVariationSettings: "'FILL' 1" }}>check_circle</span>
                          완료
                        </span>
                      ) : (
                        <span
                          className="inline-flex items-center gap-1.5 text-[10px] font-black px-1.5 py-0.5 rounded-md w-fit"
                          style={{
                            background: "rgba(249,115,22,0.12)",
                            color: "#f97316",
                            border: "1px solid rgba(249,115,22,0.35)",
                          }}
                        >
                          <span className="relative flex h-1.5 w-1.5">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ background: "#f97316" }} />
                            <span className="relative inline-flex rounded-full h-1.5 w-1.5" style={{ background: "#f97316" }} />
                          </span>
                          대기
                        </span>
                      )}
                    </div>

                    {/* 직원 */}
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div
                        className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 transition-transform group-hover:scale-110"
                        style={{ background: gender.bg, border: `1px solid ${gender.border}` }}
                      >
                        <span
                          className="material-symbols-outlined"
                          style={{ fontSize: 22, color: gender.icon, fontVariationSettings: "'FILL' 1" }}
                        >
                          person
                        </span>
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-black text-white group-hover:text-primary transition-colors truncate">
                          {v.employee_name || v.employee_id}
                        </p>
                        <p className="text-[11px] text-on-surface-variant/60 font-bold tracking-tight truncate">
                          {v.department || "미지정"}
                        </p>
                      </div>
                    </div>

                    {/* 위반 내용 */}
                    <div className="flex items-center gap-3 pr-4 min-w-0 overflow-hidden">
                      <span
                        className="material-symbols-outlined shrink-0 transition-colors"
                        style={{ fontSize: 22, color: sev.text }}
                      >
                        {icon}
                      </span>
                      <div className="min-w-0">
                        <p className="text-xs font-black uppercase tracking-wide mb-0.5" style={{ color: sev.text }}>
                          {VIOLATION_TYPE_LABEL[v.violation_type] || v.violation_type}
                        </p>
                        <p
                          className="block min-w-0 truncate text-sm text-on-surface/80"
                          title={v.description}
                        >
                          {v.description}
                        </p>
                      </div>
                    </div>

                    {/* 심각도 배지 */}
                    <div className="flex justify-center">
                      <span
                        className="px-2 py-1 text-[11px] font-black rounded-md tracking-tight"
                        style={{
                          background: sev.bg,
                          color: sev.text,
                          border: `1px solid ${sev.border}`,
                          boxShadow: isCritical ? `0 0 10px ${sev.dot}55` : "none",
                        }}
                      >
                        {sev.label}
                      </span>
                    </div>

                    {/* 조치 */}
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span
                        className="material-symbols-outlined shrink-0"
                        style={{ fontSize: 16, color: sanction.color }}
                      >
                        {sanction.icon}
                      </span>
                      <span className="text-xs font-bold tracking-tight truncate" style={{ color: sanction.color }}>
                        {sanction.label}
                      </span>
                    </div>

                    {/* 시각 — 컴팩트 (시간 + 상대시각) */}
                    <div className="text-right" title={dt.full}>
                      <p className="text-xs font-mono font-bold text-white tabular-nums leading-tight">{dt.time}</p>
                      <p className="text-[10px] text-on-surface-variant/60 font-bold mt-0.5">{timeAgo(v.created_at)}</p>
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
              minWidth: VIOLATION_TABLE_MIN_WIDTH,
              background: "rgba(255,255,255,0.02)",
              borderColor: "rgba(255,255,255,0.06)",
            }}
          >
            <p className="text-xs text-on-surface-variant/60 font-bold tracking-tight">
              {filtered.length === 0 ? 0 : (page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, filtered.length)} / {filtered.length.toLocaleString()}건
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
        </div>

        {/* ─── 상세 드로어 ─── */}
        {selectedViolation && (() => {
          const sev = SEVERITY_CONFIG[selectedViolation.severity] || SEVERITY_CONFIG.medium;
          const sanctionKey = deriveSanctionKey(selectedViolation);
          const sanction = SANCTION_META[sanctionKey] || { label: sanctionKey, color: "#8aa8b8", icon: "info" };
          const drawerGender = genderColors(selectedViolation.id);
          const violationDt = formatDate(selectedViolation.created_at);
          const chat = detailContext?.chat;
          const violationTypeLabel = VIOLATION_TYPE_LABEL[selectedViolation.violation_type] || selectedViolation.violation_type;
          return (
            <div className="fixed inset-0 z-[60] flex animate-[fadeIn_0.2s_ease-out]" onClick={() => setSelectedViolation(null)}>
              <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" />
              <div
                className="fixed right-4 top-4 bottom-4 w-[560px] max-w-[95vw] rounded-3xl z-[70] flex flex-col overflow-hidden animate-[slideInRight_0.3s_cubic-bezier(0.16,1,0.3,1)]"
                style={{
                  background: "rgba(7,24,36,0.98)",
                  border: `1px solid ${sev.border}`,
                  boxShadow: `0 0 60px rgba(0,0,0,0.8), 0 0 40px ${sev.dot}33`,
                }}
                onClick={(e) => e.stopPropagation()}
              >
                {/* 드로어 헤더 */}
                <div
                  className="p-6 flex items-center justify-between border-b shrink-0"
                  style={{ borderColor: "rgba(255,255,255,0.06)" }}
                >
                  <div className="flex items-center gap-4">
                    <div
                      className="w-14 h-14 rounded-2xl flex items-center justify-center"
                      style={{
                        background: sev.bg,
                        border: `1px solid ${sev.border}`,
                        boxShadow: `0 0 20px ${sev.dot}33`,
                      }}
                    >
                      <span
                        className="material-symbols-outlined"
                        style={{ fontSize: 30, color: sev.text, fontVariationSettings: "'FILL' 1" }}
                      >
                        gavel
                      </span>
                    </div>
                    <div>
                      <h3 className="text-xl font-black text-white">위반 상세 정보</h3>
                      <p className="text-xs font-mono tracking-wide mt-1 flex items-center gap-2" style={{ color: sev.text }}>
                        <span className="font-black">#AS-{String(selectedViolation.id).padStart(4, "0")}</span>
                        <span className="text-on-surface-variant/40">·</span>
                        <span className="text-on-surface-variant/60">{violationDt.full}</span>
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedViolation(null)}
                    className="p-2.5 rounded-xl transition-all text-on-surface-variant/40 hover:text-white hover:bg-white/8 hover:rotate-90 duration-200"
                  >
                    <span className="material-symbols-outlined">close</span>
                  </button>
                </div>

                <div className="flex-1 overflow-y-auto p-6 space-y-5">
                  {/* 대상자 */}
                  <div>
                    <p className="text-xs font-black text-on-surface-variant/60 tracking-tight uppercase mb-2.5">대상자</p>
                    <div
                      className="flex items-center gap-4 p-4 rounded-2xl"
                      style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" }}
                    >
                      <div
                        className="w-16 h-16 rounded-2xl flex items-center justify-center shrink-0"
                        style={{ background: drawerGender.bg, border: `2px solid ${drawerGender.border}` }}
                      >
                        <span
                          className="material-symbols-outlined"
                          style={{ fontSize: 38, color: drawerGender.icon, fontVariationSettings: "'FILL' 1" }}
                        >
                          person
                        </span>
                      </div>
                      <div className="min-w-0">
                        <p className="text-xl font-black text-white truncate">{selectedViolation.employee_name || selectedViolation.employee_id}</p>
                        <p className="text-sm font-bold tracking-tight text-on-surface-variant/70 truncate">
                          {selectedViolation.department || "미지정"}
                          {detailContext?.employee?.role && <span className="text-on-surface-variant/40"> · {detailContext.employee.role}</span>}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* 위반 분류 + 메타 */}
                  <div>
                    <p className="text-xs font-black text-on-surface-variant/60 tracking-tight uppercase mb-2.5">위반 분류</p>
                    <div
                      className="p-4 rounded-2xl space-y-3"
                      style={{
                        background: sev.bg,
                        borderLeft: `3px solid ${sev.text}`,
                        borderTop: `1px solid ${sev.border}`,
                        borderRight: `1px solid ${sev.border}`,
                        borderBottom: `1px solid ${sev.border}`,
                      }}
                    >
                      <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined" style={{ fontSize: 20, color: sev.text }}>
                          {VIOLATION_ICON[selectedViolation.violation_type] || VIOLATION_ICON.default}
                        </span>
                        <p className="text-base font-black tracking-tight" style={{ color: sev.text }}>
                          {violationTypeLabel}
                        </p>
                      </div>
                      <p className="text-sm text-white/85 leading-relaxed">{selectedViolation.description}</p>
                    </div>
                  </div>

                  {/* 심각도 + 조치 + 발생 시각 */}
                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <p className="text-[11px] font-black text-on-surface-variant/60 tracking-tight uppercase mb-2">심각도</p>
                      <div
                        className="px-3 py-3 rounded-xl flex flex-col items-center gap-1.5"
                        style={{ background: sev.bg, border: `1px solid ${sev.border}` }}
                      >
                        <span className="w-2.5 h-2.5 rounded-full" style={{ background: sev.dot, boxShadow: `0 0 8px ${sev.dot}` }} />
                        <span className="text-sm font-black" style={{ color: sev.text }}>{sev.label}</span>
                      </div>
                    </div>
                    <div>
                      <p className="text-[11px] font-black text-on-surface-variant/60 tracking-tight uppercase mb-2">조치</p>
                      <div
                        className="px-3 py-3 rounded-xl flex flex-col items-center gap-1.5"
                        style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)" }}
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: 18, color: sanction.color }}>{sanction.icon}</span>
                        <span className="text-xs font-black text-center leading-tight" style={{ color: sanction.color }}>{sanction.label}</span>
                      </div>
                    </div>
                    <div>
                      <p className="text-[11px] font-black text-on-surface-variant/60 tracking-tight uppercase mb-2">발생</p>
                      <div
                        className="px-3 py-3 rounded-xl flex flex-col items-center gap-1.5"
                        style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)" }}
                      >
                        <span className="material-symbols-outlined text-on-surface-variant/60" style={{ fontSize: 18 }}>schedule</span>
                        <span className="text-xs font-black text-white">{timeAgo(selectedViolation.created_at)}</span>
                      </div>
                    </div>
                  </div>

                  {/* 채팅 기록 */}
                  <div>
                    <div className="flex items-center justify-between mb-2.5">
                      <p className="text-xs font-black text-on-surface-variant/60 tracking-tight uppercase">채팅 기록</p>
                      {chat?.request_at && (
                        <span className="text-[11px] font-mono text-on-surface-variant/50">
                          {formatDate(chat.request_at).full}
                        </span>
                      )}
                    </div>

                    {detailLoading ? (
                      <div className="py-8 flex flex-col items-center gap-3 rounded-2xl" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)" }}>
                        <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                        <p className="text-xs text-on-surface-variant/60">채팅 기록 불러오는 중...</p>
                      </div>
                    ) : !chat ? (
                      <div className="py-8 flex flex-col items-center gap-2 rounded-2xl" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)" }}>
                        <span className="material-symbols-outlined text-on-surface-variant/40" style={{ fontSize: 32 }}>chat_bubble_outline</span>
                        <p className="text-xs text-on-surface-variant/50">연결된 채팅 기록이 없습니다.</p>
                      </div>
                    ) : (
                      <div className="space-y-2.5">
                        {/* User message */}
                        {chat.request_content && (
                          <div className="flex gap-2.5">
                            <div
                              className="w-8 h-8 rounded-full flex items-center justify-center shrink-0"
                              style={{ background: drawerGender.bg, border: `1px solid ${drawerGender.border}` }}
                            >
                              <span className="material-symbols-outlined" style={{ fontSize: 18, color: drawerGender.icon }}>person</span>
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-[10px] font-black text-on-surface-variant/50 tracking-wide uppercase mb-1">
                                직원 입력
                              </p>
                              <div
                                className="p-3.5 rounded-2xl rounded-tl-sm"
                                style={{ background: "rgba(96,165,250,0.06)", border: "1px solid rgba(96,165,250,0.15)" }}
                              >
                                <p className="text-sm text-white/90 leading-relaxed whitespace-pre-wrap break-words">
                                  {chat.request_content}
                                </p>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* AI response */}
                        {chat.response_content && (
                          <div className="flex gap-2.5">
                            <div
                              className="w-8 h-8 rounded-full flex items-center justify-center shrink-0"
                              style={{ background: sev.bg, border: `1px solid ${sev.border}` }}
                            >
                              <span className="material-symbols-outlined" style={{ fontSize: 18, color: sev.text, fontVariationSettings: "'FILL' 1" }}>shield</span>
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-[10px] font-black tracking-wide uppercase mb-1" style={{ color: sev.text }}>
                                AgentShield 응답
                              </p>
                              <div
                                className="p-3.5 rounded-2xl rounded-tl-sm"
                                style={{ background: sev.bg, border: `1px solid ${sev.border}` }}
                              >
                                <p className="text-sm text-white/90 leading-relaxed whitespace-pre-wrap break-words">
                                  {chat.response_content}
                                </p>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* 시스템 메타 */}
                        {(chat.action_taken || chat.target_service) && (
                          <div className="ml-10 flex flex-wrap items-center gap-2 pt-1">
                            {chat.action_taken && (
                              <span className="text-[10px] font-mono font-bold px-2 py-1 rounded-md bg-white/[0.04] text-on-surface-variant/70 border border-white/5">
                                action: {chat.action_taken}
                              </span>
                            )}
                            {chat.target_service && (
                              <span className="text-[10px] font-mono font-bold px-2 py-1 rounded-md bg-white/[0.04] text-on-surface-variant/70 border border-white/5 truncate max-w-[280px]" title={chat.target_service}>
                                {chat.target_service}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* 푸터 — 검토 완료 버튼 */}
                <div
                  className="p-5 border-t flex items-center gap-3 shrink-0"
                  style={{
                    borderColor: "rgba(255,255,255,0.06)",
                    background: "rgba(0,0,0,0.3)",
                  }}
                >
                  <div className="flex-1 flex items-center gap-2.5">
                    <span
                      className="material-symbols-outlined"
                      style={{
                        fontSize: 20,
                        color: selectedViolation.resolved ? "#22c55e" : "#f97316",
                      }}
                    >
                      {selectedViolation.resolved ? "task_alt" : "pending"}
                    </span>
                    <div>
                      <p className="text-[10px] font-black tracking-widest uppercase text-on-surface-variant/50">처리 상태</p>
                      <p
                        className="text-sm font-black"
                        style={{ color: selectedViolation.resolved ? "#22c55e" : "#f97316" }}
                      >
                        {selectedViolation.resolved ? "검토 완료" : "처리 대기 중"}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => handleResolve(selectedViolation.id)}
                    disabled={selectedViolation.resolved || resolveBusy}
                    className="flex items-center gap-2 px-5 py-3 rounded-xl text-sm font-black transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{
                      background: selectedViolation.resolved ? "rgba(34,197,94,0.15)" : "var(--primary, #0ea5a5)",
                      color: selectedViolation.resolved ? "#22c55e" : "#ffffff",
                      boxShadow: selectedViolation.resolved ? "none" : "0 4px 16px rgba(14,165,165,0.3)",
                    }}
                  >
                    {resolveBusy ? (
                      <>
                        <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                        처리 중...
                      </>
                    ) : selectedViolation.resolved ? (
                      <>
                        <span className="material-symbols-outlined" style={{ fontSize: 18 }}>check_circle</span>
                        검토 완료됨
                      </>
                    ) : (
                      <>
                        <span className="material-symbols-outlined" style={{ fontSize: 18 }}>done_all</span>
                        검토 완료
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          );
        })()}
        </>
        )}
        </div>

        {/* ─── 우측 1:1 챗봇 (lg 이상에서 sticky) ─── */}
        <aside className="lg:sticky lg:top-4 lg:self-start lg:h-[calc(100vh-8rem)] min-h-[460px]">
          <MonitoringChatPanel onMessageProcessed={loadDashboard} />
        </aside>
       </div>
      </div>
    </DashboardLayout>
  );
}
