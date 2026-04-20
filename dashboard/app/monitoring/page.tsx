"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import DashboardLayout from "../../components/DashboardLayout";
import {
  getMonitoringDashboard,
  getViolations,
  Violation,
} from "../../lib/api";

/** 현재 페이지를 중심으로 최대 `max`개의 페이지 번호만 표시 */
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

const SEVERITY_CONFIG: Record<string, { cls: string; label: string; dotCls: string }> = {
  critical: {
    cls: "bg-error/10 text-error border-error/20 shadow-[0_0_10px_rgba(255,180,171,0.1)]",
    label: "긴급",
    dotCls: "bg-error",
  },
  high: {
    cls: "bg-primary/10 text-primary border-primary/20",
    label: "높음",
    dotCls: "bg-primary",
  },
  medium: {
    cls: "bg-surface-variant text-on-surface-variant border-outline-variant/30",
    label: "중간",
    dotCls: "bg-outline-variant",
  },
  low: {
    cls: "bg-tertiary/10 text-tertiary border-tertiary/20",
    label: "낮음",
    dotCls: "bg-tertiary",
  },
};

const VIOLATION_ICON: Record<string, string> = {
  P1_leak: "data_loss_prevention",
  P2_misuse: "terminal",
  P3_ratelimit: "speed",
  default: "security",
};

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
      const [dash, viols] = await Promise.all([
        getMonitoringDashboard(),
        getViolations(),
      ]);
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

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  async function applyFilters() {
    try {
      const viols = await getViolations({
        department: deptFilter || undefined,
        violation_type: typeFilter || undefined,
      });
      setViolations(viols);
      setPage(1);
    } catch {
      // 에러 무시
    }
  }

  function resetFilters() {
    setDeptFilter("");
    setTypeFilter("");
    getViolations()
      .then((v) => {
        setViolations(v);
        setLoadError(false);
      })
      .catch(() => setLoadError(true));
    setPage(1);
  }

  const paged = violations.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.ceil(violations.length / PAGE_SIZE);

  function formatDate(iso: string) {
    const d = new Date(iso);
    return {
      date: d.toLocaleDateString("ko-KR", { year: "numeric", month: "2-digit", day: "2-digit" }),
      time: d.toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    };
  }

  const SANCTION_LABEL: Record<string, { label: string; dotCls: string }> = {
    blocked: { label: "세션 차단됨", dotCls: "bg-error" },
    warned: { label: "경고 발송됨", dotCls: "bg-primary" },
    logged: { label: "관리자 알림", dotCls: "bg-outline-variant" },
    masked: { label: "마스킹 및 기록됨", dotCls: "bg-primary" },
  };

  return (
    <DashboardLayout>
      <div className="p-10 space-y-8 max-w-[1700px] mx-auto w-full">
        {/* 헤더 */}
        <div className="flex items-end justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-[0.2em]">
              <span className="w-8 h-px bg-primary" />
              AI Usage Sentinel
            </div>
            <h2 className="text-4xl font-headline font-extrabold tracking-tight text-white">
              모니터링 및 위반
            </h2>
            <p className="text-on-surface-variant max-w-xl">
              직원 AI 사용 현황을 실시간으로 감시하고 정책 위반을 탐지합니다.
            </p>
            <p className="text-[11px] text-outline pt-1">
              정책 규칙 편집은{" "}
              <Link
                href="/monitoring/admin"
                className="text-primary/90 hover:text-primary font-bold underline-offset-2 hover:underline"
              >
                관리자
              </Link>
              화면에서 할 수 있습니다.
            </p>
          </div>
          <div className="bg-surface-container-high/40 px-5 py-2.5 rounded-xl border border-white/10 backdrop-blur-sm">
            <span className="text-[10px] block font-black text-outline tracking-widest uppercase mb-0.5">
              시스템 상태
            </span>
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-tertiary shadow-[0_0_10px_rgba(60,227,106,0.6)] animate-pulse" />
              <span className="text-sm font-bold text-tertiary tracking-tight">ACTIVE SENTINEL</span>
            </div>
          </div>
        </div>

        {loadError && (
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-error/30 bg-error/10 px-5 py-4">
            <p className="text-sm text-error font-medium">
              대시보드 데이터를 불러오지 못했습니다. 네트워크·백엔드 상태를 확인한 뒤 다시 시도해 주세요.
            </p>
            <button
              type="button"
              onClick={() => loadDashboard()}
              className="shrink-0 px-4 py-2 rounded-xl text-xs font-black uppercase tracking-wider bg-on-surface text-background hover:opacity-90 transition-opacity"
            >
              다시 시도
            </button>
          </div>
        )}

        {/* 통계 카드 */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-5">
          {[
            {
              icon: "bar_chart",
              label: "오늘 AI 요청",
              value: loading ? "—" : (dashboard?.daily_requests ?? 0).toLocaleString(),
              sub: "DAILY REQUESTS",
              hoverCls: "hover:border-tertiary/20",
              valueCls: "text-tertiary",
            },
            {
              icon: "warning",
              label: "총 위반 건수",
              value: loading ? "—" : (dashboard?.violations_count ?? 0).toLocaleString(),
              sub: "TOTAL",
              hoverCls: "hover:border-primary/20",
              valueCls: "text-on-surface",
            },
            {
              icon: "priority_high",
              label: "심각한 경고",
              value: loading ? "—" : violations.filter((v) => v.severity === "critical").length,
              sub: "ACTION REQUIRED",
              hoverCls: "hover:border-error/20",
              valueCls: "text-error",
            },
            {
              icon: "group",
              label: "모니터링 대상",
              value: loading ? "—" : (dashboard?.total_employees ?? 0).toLocaleString(),
              sub: `${dashboard?.active_employees ?? 0} ACTIVE`,
              hoverCls: "hover:border-primary/20",
              valueCls: "text-on-surface",
            },
            {
              icon: "block",
              label: "차단된 세션",
              value: loading ? "—" : (dashboard?.blocked_count ?? 0).toLocaleString(),
              sub: "BLOCKED TODAY",
              hoverCls: "hover:border-error/20",
              valueCls: "text-primary",
            },
          ].map((card) => (
            <div
              key={card.label}
              className={`bg-surface-container-low p-6 rounded-2xl border border-white/5 relative overflow-hidden group transition-all ${card.hoverCls}`}
            >
              <div className="absolute -right-6 -top-6 opacity-[0.03] group-hover:opacity-[0.08] transition-opacity rotate-12">
                <span className="material-symbols-outlined text-9xl">{card.icon}</span>
              </div>
              <p className="text-[10px] font-black text-outline tracking-widest font-headline uppercase">
                {card.label}
              </p>
              <h3 className={`text-4xl font-black mt-3 tracking-tighter ${card.valueCls}`}>
                {card.value}
              </h3>
              <p className="text-xs text-on-surface-variant mt-4 font-bold uppercase tracking-tight">
                {card.sub}
              </p>
            </div>
          ))}
        </div>

        {/* 필터 바 */}
        <div className="bg-surface-container-high/40 p-4 rounded-2xl flex flex-wrap gap-4 items-end border border-white/5 backdrop-blur-md">
          <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="space-y-1.5">
              <label className="text-[10px] font-black text-outline tracking-widest uppercase ml-1">
                부서
              </label>
              <select
                value={deptFilter}
                onChange={(e) => setDeptFilter(e.target.value)}
                className="w-full bg-surface-container-lowest border border-white/10 rounded-xl text-xs px-3 py-2.5 text-on-surface focus:ring-1 focus:ring-primary/40 focus:outline-none transition-all"
              >
                <option value="">전체 부서</option>
                <option value="Engineering">엔지니어링</option>
                <option value="Marketing">제품 마케팅</option>
                <option value="Finance">재무</option>
                <option value="HR">인사</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-[10px] font-black text-outline tracking-widest uppercase ml-1">
                위반 유형
              </label>
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="w-full bg-surface-container-lowest border border-white/10 rounded-xl text-xs px-3 py-2.5 text-on-surface focus:ring-1 focus:ring-primary/40 focus:outline-none transition-all"
              >
                <option value="">전체 유형</option>
                <option value="P1_leak">데이터 유출</option>
                <option value="P2_misuse">부적절한 프롬프트</option>
                <option value="P3_ratelimit">속도 제한 초과</option>
              </select>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={applyFilters}
              className="px-5 py-2.5 text-xs font-black tracking-widest text-on-primary bg-primary rounded-xl hover:bg-primary/80 transition-colors uppercase"
            >
              필터 적용
            </button>
            <button
              onClick={resetFilters}
              className="px-5 py-2.5 text-xs font-black tracking-widest text-outline hover:text-on-surface transition-colors uppercase"
            >
              초기화
            </button>
          </div>
        </div>

        {/* 위반 테이블 */}
        <div className="bg-surface-container-low rounded-2xl overflow-hidden border border-white/5 shadow-2xl">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-container-highest/30 border-b border-white/10">
                <th className="px-6 py-5 text-[10px] font-black text-outline tracking-widest uppercase">LOG_ID</th>
                <th className="px-6 py-5 text-[10px] font-black text-outline tracking-widest uppercase">IDENTITY</th>
                <th className="px-6 py-5 text-[10px] font-black text-outline tracking-widest uppercase">VIOLATION_TYPE</th>
                <th className="px-6 py-5 text-[10px] font-black text-outline tracking-widest uppercase text-center">SEVERITY</th>
                <th className="px-6 py-5 text-[10px] font-black text-outline tracking-widest uppercase">ENFORCEMENT</th>
                <th className="px-6 py-5 text-[10px] font-black text-outline tracking-widest uppercase text-right">TIMESTAMP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-6 py-16 text-center">
                    <div className="flex flex-col items-center gap-4">
                      <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                      <p className="text-sm text-on-surface-variant">데이터 불러오는 중...</p>
                    </div>
                  </td>
                </tr>
              ) : paged.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-16 text-center">
                    <p className="text-sm text-on-surface-variant">위반 내역이 없습니다.</p>
                  </td>
                </tr>
              ) : (
                paged.map((v, idx) => {
                  const sev = SEVERITY_CONFIG[v.severity] || SEVERITY_CONFIG.medium;
                  const icon = VIOLATION_ICON[v.violation_type] || VIOLATION_ICON.default;
                  const sanction = SANCTION_LABEL[v.sanction] || { label: v.sanction, dotCls: "bg-outline" };
                  const dt = formatDate(v.created_at);
                  const rowBg = idx % 2 === 1 ? "bg-surface-container-high/10" : "";

                  return (
                    <tr
                      key={v.id}
                      onClick={() => setSelectedViolation(v)}
                      className={`transition-all cursor-pointer group hover:bg-primary/5 ${rowBg}`}
                    >
                      <td className="px-6 py-5 font-mono text-xs text-primary font-bold">
                        #AS-{String(v.id).padStart(4, "0")}
                      </td>
                      <td className="px-6 py-5">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-xl bg-surface-container-high border border-white/10 flex items-center justify-center">
                            <span className="material-symbols-outlined text-on-surface-variant text-sm">
                              person
                            </span>
                          </div>
                          <div>
                            <p className="text-sm font-bold text-on-surface group-hover:text-primary transition-colors">
                              {v.employee_name || v.employee_id}
                            </p>
                            <p className="text-[10px] text-outline uppercase font-black tracking-tighter">
                              {v.department || "—"}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-5">
                        <div className="flex items-center gap-2.5">
                          <span className="material-symbols-outlined text-base text-outline group-hover:text-primary transition-colors">
                            {icon}
                          </span>
                          <span className="text-sm text-on-surface font-medium">{v.description}</span>
                        </div>
                      </td>
                      <td className="px-6 py-5 text-center">
                        <span className={`px-3 py-1 text-[10px] font-black rounded border uppercase tracking-widest ${sev.cls}`}>
                          {sev.label}
                        </span>
                      </td>
                      <td className="px-6 py-5">
                        <div className="flex items-center gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full ${sanction.dotCls}`} />
                          <span className="text-xs text-on-surface-variant font-bold uppercase tracking-tight">
                            {sanction.label}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-5 text-right text-[11px] text-outline font-mono">
                        {dt.date}{" "}
                        <span className="text-on-surface-variant font-bold">{dt.time}</span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>

          {/* 페이지네이션 */}
          <div className="px-6 py-5 bg-surface-container-low border-t border-white/5 flex justify-between items-center">
            <p className="text-[11px] text-outline font-bold tracking-tight uppercase">
              DISPLAYING {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, violations.length)} OF{" "}
              {violations.length} ENTRIES
            </p>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-2 rounded-lg hover:bg-surface-container-highest text-outline transition-colors disabled:opacity-30"
              >
                <span className="material-symbols-outlined text-sm">chevron_left</span>
              </button>
              {visiblePageNumbers(page, totalPages, 5).map((p) => (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  className={`w-8 h-8 rounded-lg text-xs font-black transition-colors ${
                    page === p
                      ? "bg-primary text-on-primary shadow-lg shadow-primary/20"
                      : "hover:bg-surface-container-highest text-outline"
                  }`}
                >
                  {p}
                </button>
              ))}
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages || totalPages === 0}
                className="p-2 rounded-lg hover:bg-surface-container-highest text-outline transition-colors disabled:opacity-30"
              >
                <span className="material-symbols-outlined text-sm">chevron_right</span>
              </button>
            </div>
          </div>
        </div>

        {/* 상세 드로어 */}
        {selectedViolation && (
          <div className="fixed inset-0 z-[60] flex" onClick={() => setSelectedViolation(null)}>
            <div className="absolute inset-0 bg-background/60 backdrop-blur-sm" />
            <div
              className="fixed right-4 top-4 bottom-4 w-[480px] glass-panel rounded-3xl shadow-[0_0_80px_rgba(0,0,0,0.8)] z-[70] flex flex-col border border-white/10 overflow-y-auto"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="p-8 flex items-center justify-between border-b border-white/5 sticky top-0 bg-surface-container/80 backdrop-blur-lg z-10">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-error/10 border border-error/20 rounded-2xl flex items-center justify-center shadow-inner">
                    <span className="material-symbols-outlined text-error text-2xl" style={{ fontVariationSettings: "'FILL' 1" }}>
                      gavel
                    </span>
                  </div>
                  <div>
                    <h3 className="text-xl font-black font-headline text-on-surface tracking-tight">
                      위반 상세 정보
                    </h3>
                    <p className="text-[10px] text-primary font-mono tracking-widest uppercase mt-0.5">
                      RECORD_ID: #AS-{String(selectedViolation.id).padStart(4, "0")}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedViolation(null)}
                  className="p-2.5 hover:bg-white/10 rounded-xl transition-all text-outline"
                >
                  <span className="material-symbols-outlined">close</span>
                </button>
              </div>

              <div className="p-8 space-y-8">
                {/* 대상자 정보 */}
                <div className="space-y-4">
                  <h4 className="text-[11px] font-black text-outline tracking-widest uppercase flex items-center gap-2">
                    <span className="w-1.5 h-1.5 bg-primary rounded-full" /> 대상자 정보
                  </h4>
                  <div className="bg-black/20 p-5 rounded-2xl flex items-center gap-5 border border-white/5">
                    <div className="w-16 h-16 rounded-2xl border-2 border-primary/30 bg-surface-container-high flex items-center justify-center">
                      <span className="material-symbols-outlined text-primary text-2xl">person</span>
                    </div>
                    <div>
                      <p className="text-lg font-black text-on-surface">
                        {selectedViolation.employee_name || selectedViolation.employee_id}
                      </p>
                      <p className="text-xs text-outline font-bold uppercase tracking-tight">
                        {selectedViolation.department || "미지정 부서"}
                      </p>
                    </div>
                  </div>
                </div>

                {/* 위반 내용 */}
                <div className="space-y-4">
                  <h4 className="text-[11px] font-black text-outline tracking-widest uppercase flex items-center gap-2">
                    <span className="w-1.5 h-1.5 bg-error rounded-full" /> 위반 내용
                  </h4>
                  <div className="bg-error/5 border-l-4 border-error p-5 rounded-r-2xl space-y-2">
                    <p className="text-xs font-bold text-error uppercase tracking-widest">
                      {selectedViolation.violation_type}
                    </p>
                    <p className="text-sm text-on-surface leading-relaxed">{selectedViolation.description}</p>
                  </div>
                </div>

                {/* 적용된 조치 */}
                <div className="space-y-4">
                  <h4 className="text-[11px] font-black text-outline tracking-widest uppercase flex items-center gap-2">
                    <span className="w-1.5 h-1.5 bg-tertiary rounded-full" /> 적용된 조치
                  </h4>
                  <div className="flex items-center gap-4 p-4 bg-white/5 rounded-2xl border border-white/5">
                    <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
                      <span className="material-symbols-outlined text-primary" style={{ fontVariationSettings: "'FILL' 1" }}>
                        shield_lock
                      </span>
                    </div>
                    <div>
                      <p className="text-sm font-bold text-on-surface capitalize">{selectedViolation.sanction}</p>
                      <p className="text-[10px] text-outline uppercase font-bold tracking-tighter">
                        {selectedViolation.resolved ? "해결됨" : "처리 중"}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
