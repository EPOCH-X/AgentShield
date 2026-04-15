"use client";

import { useState, useEffect } from "react";
import DashboardLayout from "../../../components/DashboardLayout";
import { getPolicies, createPolicy, getEmployees, Policy, Employee } from "../../../lib/api";

const SEVERITY_CONFIG: Record<string, { cls: string; dotCls: string; glowCls: string }> = {
  critical: {
    cls: "border-error/30 text-error",
    dotCls: "bg-error animate-pulse shadow-[0_0_8px_rgba(255,180,171,0.6)]",
    glowCls: "status-badge-gradient",
  },
  high: {
    cls: "border-secondary/30 text-secondary",
    dotCls: "bg-secondary shadow-[0_0_8px_rgba(182,198,237,0.4)]",
    glowCls: "status-badge-gradient",
  },
  medium: {
    cls: "border-outline/30 text-outline",
    dotCls: "bg-outline",
    glowCls: "status-badge-gradient",
  },
  low: {
    cls: "border-tertiary/20 text-tertiary",
    dotCls: "bg-tertiary",
    glowCls: "status-badge-gradient",
  },
};

const SEV_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const ACTION_LABEL: Record<string, string> = {
  block: "차단",
  warn: "경고",
  log: "로깅",
};

export default function AdminPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({
    rule_name: "",
    rule_type: "keyword",
    pattern: "",
    severity: "high",
    action: "block",
  });
  const [formError, setFormError] = useState("");

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const [p, e] = await Promise.all([
          getPolicies(),
          getEmployees().catch(() => [] as Employee[]),
        ]);
        setPolicies(p);
        setEmployees(e);
      } catch {
        // auth 에러는 api.ts에서 처리
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  async function handleCreatePolicy(e: React.FormEvent) {
    e.preventDefault();
    if (!form.rule_name.trim() || !form.pattern.trim()) {
      setFormError("정책 이름과 패턴을 입력해 주세요.");
      return;
    }
    setFormError("");
    setSaving(true);
    try {
      const p = await createPolicy(form);
      setPolicies((prev) => [p, ...prev]);
      setShowModal(false);
      setForm({ rule_name: "", rule_type: "keyword", pattern: "", severity: "high", action: "block" });
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "정책 생성에 실패했습니다.");
    } finally {
      setSaving(false);
    }
  }

  const activePolicies = policies.filter((p) => p.is_active).length;

  return (
    <DashboardLayout>
      <div className="p-10 max-w-7xl mx-auto space-y-12">
        {/* 헤더 */}
        <section className="flex justify-between items-end">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-[0.2em] mb-1">
              <span className="w-8 h-px bg-primary" />
              Security Guardrails
            </div>
            <h2 className="text-4xl font-headline font-extrabold tracking-tight text-white">
              정책 관리
            </h2>
            <p className="text-on-surface-variant max-w-xl font-medium">
              실시간 AI 상호작용을 보호하기 위한 지능형 보안 정책을 수립하고 모니터링합니다.
            </p>
          </div>
          <button
            onClick={() => setShowModal(true)}
            className="bg-gradient-to-br from-primary via-primary-container to-[#007acc] text-on-primary px-8 py-4 rounded-2xl font-bold flex items-center gap-3 shadow-2xl shadow-primary/30 hover:shadow-primary/40 hover:-translate-y-0.5 active:translate-y-0 transition-all duration-300"
          >
            <span className="material-symbols-outlined text-xl">add_moderator</span>
            새 정책 생성
          </button>
        </section>

        {/* 메인 그리드 */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* 보안 규칙 테이블 */}
          <div className="lg:col-span-2">
            <div className="glass-panel rounded-2xl overflow-hidden shadow-2xl">
              <div className="px-8 py-6 border-b border-white/5 flex justify-between items-center bg-white/[0.02]">
                <h3 className="font-headline font-bold text-xl flex items-center gap-3 text-white">
                  <span className="material-symbols-outlined text-primary text-2xl">gpp_maybe</span>
                  활성 보안 규칙
                </h3>
                <div className="flex items-center gap-4">
                  <span className="text-[10px] font-bold uppercase tracking-widest text-primary bg-primary/10 border border-primary/20 px-3 py-1.5 rounded-lg shadow-inner">
                    Active: {activePolicies} Rules
                  </span>
                </div>
              </div>

              {loading ? (
                <div className="px-8 py-16 flex justify-center">
                  <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                </div>
              ) : policies.length === 0 ? (
                <div className="px-8 py-16 text-center">
                  <p className="text-on-surface-variant">등록된 정책이 없습니다.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="bg-black/20 text-on-surface-variant text-[10px] uppercase tracking-widest font-extrabold">
                      <tr>
                        <th className="px-8 py-5 border-b border-white/5">Rule ID</th>
                        <th className="px-8 py-5 border-b border-white/5">정책 명칭</th>
                        <th className="px-8 py-5 border-b border-white/5">탐지 패턴</th>
                        <th className="px-8 py-5 border-b border-white/5">심각도</th>
                        <th className="px-8 py-5 border-b border-white/5">상태</th>
                        <th className="px-8 py-5 border-b border-white/5 text-right">관리</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {policies.map((policy) => {
                        const sev = SEVERITY_CONFIG[policy.severity] || SEVERITY_CONFIG.medium;
                        return (
                          <tr key={policy.id} className="row-glow transition-all duration-300 group">
                            <td className="px-8 py-6">
                              <span className="font-mono text-[10px] text-primary/60 bg-primary/5 px-2 py-1 rounded">
                                POL-{String(policy.id).padStart(3, "0")}
                              </span>
                            </td>
                            <td className="px-8 py-6">
                              <div className="flex flex-col">
                                <span className="font-bold text-white group-hover:text-primary transition-colors">
                                  {policy.rule_name}
                                </span>
                                <span className="text-[10px] text-on-surface-variant mt-1">
                                  {ACTION_LABEL[policy.action] || policy.action} · {policy.rule_type}
                                </span>
                              </div>
                            </td>
                            <td className="px-8 py-6">
                              <code className="text-[10px] bg-black/40 px-3 py-1.5 rounded-lg border border-white/5 text-on-surface-variant font-mono">
                                {policy.pattern.length > 30
                                  ? policy.pattern.slice(0, 30) + "..."
                                  : policy.pattern}
                              </code>
                            </td>
                            <td className="px-8 py-6">
                              <span
                                className={`${sev.glowCls} border ${sev.cls} px-3 py-1.5 rounded-full flex items-center gap-2 w-fit`}
                              >
                                <span className={`w-1.5 h-1.5 rounded-full ${sev.dotCls}`} />
                                <span className="text-[10px] font-black uppercase tracking-wider">
                                  {SEV_LABEL[policy.severity] || policy.severity}
                                </span>
                              </span>
                            </td>
                            <td className="px-8 py-6">
                              <div
                                className={`w-11 h-6 rounded-full border relative p-1 cursor-default ${
                                  policy.is_active
                                    ? "toggle-active border-transparent"
                                    : "bg-white/5 border-white/10"
                                }`}
                              >
                                <div
                                  className={`w-4 h-4 bg-white rounded-full shadow-lg transform transition-transform ${
                                    policy.is_active ? "translate-x-5" : "translate-x-0"
                                  }`}
                                />
                              </div>
                            </td>
                            <td className="px-8 py-6 text-right">
                              <div className="flex justify-end gap-2">
                                <button className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-primary/20 text-on-surface-variant hover:text-primary transition-all">
                                  <span className="material-symbols-outlined text-lg">edit</span>
                                </button>
                                <button className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-error/20 text-on-surface-variant hover:text-error transition-all">
                                  <span className="material-symbols-outlined text-lg">delete_forever</span>
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* 사이드 패널 */}
          <div className="space-y-8">
            {/* 직원 관리 */}
            <div className="glass-panel-elevated rounded-2xl p-8 border-t-2 border-primary shadow-2xl">
              <div className="flex justify-between items-center mb-8">
                <h3 className="font-headline font-bold text-lg flex items-center gap-3 text-white">
                  <span className="material-symbols-outlined text-primary">badge</span>
                  보안 관리 직원
                </h3>
                <button className="text-primary text-[10px] font-black uppercase tracking-widest hover:text-primary-fixed transition-colors">
                  View All
                </button>
              </div>
              <div className="space-y-4">
                {loading ? (
                  <div className="flex justify-center py-8">
                    <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  </div>
                ) : employees.length === 0 ? (
                  <p className="text-xs text-on-surface-variant text-center py-8">직원 데이터 없음</p>
                ) : (
                  employees.slice(0, 4).map((emp) => (
                    <div
                      key={emp.id}
                      className="group/emp bg-white/[0.03] hover:bg-white/[0.08] border border-white/5 p-4 rounded-2xl flex items-center justify-between transition-all duration-300"
                    >
                      <div className="flex items-center gap-4">
                        <div className="relative">
                          <div className="w-12 h-12 rounded-xl bg-surface-container-high border border-white/10 flex items-center justify-center">
                            <span className="material-symbols-outlined text-on-surface-variant">person</span>
                          </div>
                          <span
                            className={`absolute -bottom-1 -right-1 w-3.5 h-3.5 rounded-full border-2 border-[#1e293b] ${
                              emp.status === "active" ? "bg-tertiary shadow-sm shadow-tertiary/40" : "bg-error shadow-sm shadow-error/40"
                            }`}
                          />
                        </div>
                        <div>
                          <p className="font-bold text-sm text-white group-hover/emp:text-primary transition-colors">
                            {emp.name}
                          </p>
                          <p className="text-[9px] font-bold text-on-surface-variant flex items-center gap-1.5 uppercase mt-0.5 tracking-tighter">
                            <span
                              className={`material-symbols-outlined text-[10px] ${
                                emp.status === "active" ? "text-tertiary" : "text-error"
                              }`}
                            >
                              {emp.status === "active" ? "check_circle" : "cancel"}
                            </span>
                            {emp.department}
                          </p>
                        </div>
                      </div>
                      <button className="bg-surface-container-high hover:bg-primary/20 text-[10px] font-black px-3 py-1.5 rounded-lg border border-white/5 transition-colors text-on-surface-variant hover:text-primary">
                        상세
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* 시스템 상태 카드 */}
            <div className="bg-gradient-to-br from-[#0d1c32] via-[#1c2a41] to-background p-8 rounded-2xl shadow-2xl border border-primary/20 relative overflow-hidden group">
              <div className="absolute top-0 right-0 w-32 h-32 bg-primary/10 blur-[60px] rounded-full group-hover:bg-primary/20 transition-all duration-700" />
              <div className="relative z-10">
                <p className="text-primary/60 text-[10px] uppercase tracking-[0.3em] font-black mb-2">
                  Enforcement Engine
                </p>
                <div className="flex items-baseline gap-2">
                  <h4 className="text-4xl font-headline font-black text-white">99.9%</h4>
                  <span className="text-tertiary text-xs font-bold">Optimal</span>
                </div>
                <div className="mt-6 h-1.5 w-full bg-black/40 rounded-full overflow-hidden border border-white/5">
                  <div
                    className="h-full rounded-full shadow-[0_0_15px_rgba(152,203,255,0.6)]"
                    style={{
                      width: "99.9%",
                      background: "linear-gradient(to right, #98cbff, #3ce36a)",
                    }}
                  />
                </div>
                <div className="mt-5 flex justify-between items-center">
                  <p className="text-[10px] text-on-surface-variant font-bold uppercase tracking-wider">
                    Policies: {policies.length}
                  </p>
                  <span className="flex items-center gap-1 text-[10px] text-tertiary font-bold uppercase">
                    <span className="w-1 h-1 rounded-full bg-tertiary animate-pulse" />
                    Encrypted
                  </span>
                </div>
              </div>
              <span className="material-symbols-outlined absolute -bottom-8 -right-8 text-[120px] text-white/5 pointer-events-none group-hover:scale-110 transition-transform duration-700">
                security_update_good
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 정책 생성 모달 */}
      {showModal && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center p-6"
          onClick={() => setShowModal(false)}
        >
          <div className="absolute inset-0 bg-background/80 backdrop-blur-xl" />
          <div
            className="bg-surface-container-low w-full max-w-xl rounded-2xl shadow-2xl border border-white/10 overflow-hidden relative z-10"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-8 border-b border-white/5 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center">
                  <span className="material-symbols-outlined text-primary text-2xl">add_moderator</span>
                </div>
                <div>
                  <h3 className="text-xl font-black font-headline text-white">새 정책 생성</h3>
                  <p className="text-[10px] text-on-surface-variant mt-0.5">AI 상호작용 보안 규칙을 정의합니다</p>
                </div>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="p-2.5 hover:bg-white/10 rounded-xl transition-all text-outline"
              >
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            <form onSubmit={handleCreatePolicy} className="p-8 space-y-6">
              <div className="grid grid-cols-2 gap-5">
                <div className="space-y-2 col-span-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    정책 이름
                  </label>
                  <input
                    type="text"
                    value={form.rule_name}
                    onChange={(e) => setForm({ ...form, rule_name: e.target.value })}
                    placeholder="예: PII 비식별화 규칙"
                    className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-sm focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    규칙 유형
                  </label>
                  <select
                    value={form.rule_type}
                    onChange={(e) => setForm({ ...form, rule_type: e.target.value })}
                    className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-sm focus:border-primary/50 focus:outline-none transition-all"
                  >
                    <option value="keyword">키워드</option>
                    <option value="regex">정규식</option>
                    <option value="ratelimit">속도 제한</option>
                    <option value="topic">주제 분류</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    심각도
                  </label>
                  <select
                    value={form.severity}
                    onChange={(e) => setForm({ ...form, severity: e.target.value })}
                    className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-sm focus:border-primary/50 focus:outline-none transition-all"
                  >
                    <option value="critical">긴급 (Critical)</option>
                    <option value="high">높음 (High)</option>
                    <option value="medium">중간 (Medium)</option>
                    <option value="low">낮음 (Low)</option>
                  </select>
                </div>
                <div className="space-y-2 col-span-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    탐지 패턴
                  </label>
                  <input
                    type="text"
                    value={form.pattern}
                    onChange={(e) => setForm({ ...form, pattern: e.target.value })}
                    placeholder="예: /(\d{3}-\d{2}-\d{4})/ 또는 키워드"
                    className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-sm font-mono focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    조치
                  </label>
                  <select
                    value={form.action}
                    onChange={(e) => setForm({ ...form, action: e.target.value })}
                    className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-sm focus:border-primary/50 focus:outline-none transition-all"
                  >
                    <option value="block">차단 (Block)</option>
                    <option value="warn">경고 (Warn)</option>
                    <option value="log">로깅 (Log)</option>
                  </select>
                </div>
              </div>

              {formError && (
                <div className="flex items-center gap-3 p-4 rounded-2xl bg-error/10 border border-error/20">
                  <span className="material-symbols-outlined text-error">error</span>
                  <p className="text-sm text-error">{formError}</p>
                </div>
              )}

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="flex-1 py-4 rounded-2xl bg-white/5 border border-white/10 text-on-surface-variant hover:text-white transition-all font-bold"
                >
                  취소
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="flex-1 py-4 rounded-2xl bg-gradient-to-r from-primary to-primary-container text-on-primary-container font-extrabold shadow-lg shadow-primary/20 hover:-translate-y-0.5 transition-all disabled:opacity-50"
                >
                  {saving ? (
                    <span className="flex items-center justify-center gap-2">
                      <span className="w-4 h-4 border-2 border-on-primary-container border-t-transparent rounded-full animate-spin" />
                      생성 중...
                    </span>
                  ) : (
                    "정책 생성"
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
}
