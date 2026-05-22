"use client";

import { useState, useEffect, useCallback } from "react";
import { getPolicies, createPolicy, updatePolicy, deletePolicy, Policy } from "../lib/api";

const SEVERITY_META: Record<string, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: "긴급", color: "#ef4444", bg: "rgba(239,68,68,0.10)", border: "rgba(239,68,68,0.3)" },
  high:     { label: "높음", color: "#f97316", bg: "rgba(249,115,22,0.10)", border: "rgba(249,115,22,0.3)" },
  medium:   { label: "중간", color: "#eab308", bg: "rgba(234,179,8,0.08)", border: "rgba(234,179,8,0.28)" },
  low:      { label: "낮음", color: "#22c55e", bg: "rgba(34,197,94,0.08)", border: "rgba(34,197,94,0.25)" },
};

const ACTION_LABEL: Record<string, string> = { block: "차단", warn: "경고", log: "로깅" };
type PolicyFormState = Pick<Policy, "rule_name" | "rule_type" | "pattern" | "severity" | "action">;

const DEFAULT_FORM: PolicyFormState = {
  rule_name: "",
  rule_type: "keyword",
  pattern: "",
  severity: "high",
  action: "block",
};

export default function MonitoringPoliciesPanel() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [policyBusy, setPolicyBusy] = useState<Record<number, "toggle" | "delete">>({});
  const [form, setForm] = useState<PolicyFormState>(DEFAULT_FORM);
  const [editingPolicyId, setEditingPolicyId] = useState<number | null>(null);
  const [editForm, setEditForm] = useState<PolicyFormState>(DEFAULT_FORM);
  const [editSaving, setEditSaving] = useState(false);
  const [formError, setFormError] = useState("");
  const [editError, setEditError] = useState("");
  const [panelError, setPanelError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const p = await getPolicies();
      setPolicies(p);
    } catch {
      setPolicies([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.rule_name.trim() || !form.pattern.trim()) {
      setFormError("정책 이름과 패턴을 입력하세요.");
      return;
    }
    setFormError("");
    setSaving(true);
    try {
      const created = await createPolicy(form);
      setPolicies((prev) => [created, ...prev]);
      setForm(DEFAULT_FORM);
      setShowForm(false);
      setPanelError("");
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "정책 생성 실패");
    } finally {
      setSaving(false);
    }
  }

  function openEdit(policy: Policy) {
    setShowForm(false);
    setFormError("");
    setEditError("");
    setEditingPolicyId(policy.id);
    setEditForm({
      rule_name: policy.rule_name,
      rule_type: policy.rule_type,
      pattern: policy.pattern,
      severity: policy.severity,
      action: policy.action,
    });
  }

  async function handleEditSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (editingPolicyId == null) return;
    if (!editForm.rule_name.trim() || !editForm.pattern.trim()) {
      setEditError("정책 이름과 패턴을 입력하세요.");
      return;
    }
    setEditError("");
    setPanelError("");
    setEditSaving(true);
    try {
      const updated = await updatePolicy(editingPolicyId, editForm);
      setPolicies((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
      setEditingPolicyId(null);
      setEditForm(DEFAULT_FORM);
    } catch (err) {
      setEditError(err instanceof Error ? err.message : "정책 수정 실패");
    } finally {
      setEditSaving(false);
    }
  }

  async function handleToggle(policy: Policy) {
    setPanelError("");
    setPolicyBusy((prev) => ({ ...prev, [policy.id]: "toggle" }));
    try {
      const updated = await updatePolicy(policy.id, { is_active: !policy.is_active });
      setPolicies((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
    } catch (err) {
      setPanelError(err instanceof Error ? err.message : "정책 상태 변경 실패");
    } finally {
      setPolicyBusy((prev) => {
        const next = { ...prev };
        delete next[policy.id];
        return next;
      });
    }
  }

  async function handleDelete(policy: Policy) {
    const ok = window.confirm(`정책 "${policy.rule_name}"을 삭제할까요?\n삭제 즉시 다음 챗봇 요청부터 적용에서 제외됩니다.`);
    if (!ok) return;
    setPanelError("");
    setPolicyBusy((prev) => ({ ...prev, [policy.id]: "delete" }));
    try {
      await deletePolicy(policy.id);
      setPolicies((prev) => prev.filter((p) => p.id !== policy.id));
    } catch (err) {
      setPanelError(err instanceof Error ? err.message : "정책 삭제 실패");
    } finally {
      setPolicyBusy((prev) => {
        const next = { ...prev };
        delete next[policy.id];
        return next;
      });
    }
  }

  const activeCount = policies.filter((p) => p.is_active).length;

  return (
    <div className="space-y-4">
      {/* 헤더 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-lg font-bold text-white">보안 정책 룰</h3>
          <span className="text-[10px] font-bold uppercase tracking-widest text-primary bg-primary/10 border border-primary/20 px-2 py-0.5 rounded">
            Active {activeCount}
          </span>
        </div>
        <button
          onClick={() => {
            setShowForm((v) => !v);
            setEditingPolicyId(null);
            setEditError("");
          }}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-primary/15 border border-primary/30 text-primary text-xs font-bold hover:bg-primary/25 transition-colors"
        >
          <span className="material-symbols-outlined text-sm">{showForm ? "close" : "add"}</span>
          {showForm ? "취소" : "새 정책"}
        </button>
      </div>

      {/* 인라인 생성 폼 */}
      {showForm && (
        <form onSubmit={handleSubmit} className="rounded-xl border border-primary/20 bg-primary/5 p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">정책 이름</label>
              <input
                type="text"
                value={form.rule_name}
                onChange={(e) => setForm({ ...form, rule_name: e.target.value })}
                placeholder="예: 회사기밀 키워드 차단"
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white placeholder:text-on-surface-variant/30 focus:outline-none focus:border-primary/40"
              />
            </div>
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">탐지 패턴 (keyword 또는 regex)</label>
              <input
                type="text"
                value={form.pattern}
                onChange={(e) => setForm({ ...form, pattern: e.target.value })}
                placeholder="예: 회사기밀 또는 \\bsk-[A-Za-z0-9]{8,}\\b"
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white font-mono placeholder:text-on-surface-variant/30 focus:outline-none focus:border-primary/40"
              />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">타입</label>
              <select
                value={form.rule_type}
                onChange={(e) => setForm({ ...form, rule_type: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white focus:outline-none focus:border-primary/40"
              >
                <option value="keyword">keyword</option>
                <option value="regex">regex</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">심각도</label>
              <select
                value={form.severity}
                onChange={(e) => setForm({ ...form, severity: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white focus:outline-none focus:border-primary/40"
              >
                <option value="critical">긴급 (critical)</option>
                <option value="high">높음 (high)</option>
                <option value="medium">중간 (medium)</option>
                <option value="low">낮음 (low)</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">조치</label>
              <select
                value={form.action}
                onChange={(e) => setForm({ ...form, action: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white focus:outline-none focus:border-primary/40"
              >
                <option value="block">차단 (block)</option>
                <option value="warn">경고 (warn)</option>
                <option value="log">로깅 (log)</option>
              </select>
            </div>
          </div>
          {formError && <p className="text-xs text-error">{formError}</p>}
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 rounded-lg bg-primary text-on-primary text-sm font-bold disabled:opacity-50 hover:brightness-110 transition-all"
            >
              {saving ? "생성 중…" : "정책 생성"}
            </button>
          </div>
          <p className="text-[10px] text-on-surface-variant/40 leading-relaxed">
            생성된 정책은 다음 1:1 챗봇 요청부터 P1/P2 게이트에 즉시 반영됩니다 (severity high/critical → P1, medium/low → P2).
          </p>
        </form>
      )}

      {editingPolicyId != null && (
        <form onSubmit={handleEditSubmit} className="rounded-xl border border-tertiary/20 bg-tertiary/5 p-4 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-[10px] font-black uppercase tracking-[0.24em] text-tertiary/80">Edit Policy</p>
              <h4 className="mt-1 text-sm font-bold text-white">정책 수정</h4>
            </div>
            <button
              type="button"
              onClick={() => {
                setEditingPolicyId(null);
                setEditForm(DEFAULT_FORM);
                setEditError("");
              }}
              className="grid h-8 w-8 place-items-center rounded-lg border border-white/10 text-on-surface-variant/70 hover:bg-white/5"
              aria-label="수정 취소"
            >
              <span className="material-symbols-outlined text-[16px]">close</span>
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">정책 이름</label>
              <input
                type="text"
                value={editForm.rule_name}
                onChange={(e) => setEditForm({ ...editForm, rule_name: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white placeholder:text-on-surface-variant/30 focus:outline-none focus:border-tertiary/40"
              />
            </div>
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">탐지 패턴</label>
              <input
                type="text"
                value={editForm.pattern}
                onChange={(e) => setEditForm({ ...editForm, pattern: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white font-mono placeholder:text-on-surface-variant/30 focus:outline-none focus:border-tertiary/40"
              />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">타입</label>
              <select
                value={editForm.rule_type}
                onChange={(e) => setEditForm({ ...editForm, rule_type: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white focus:outline-none focus:border-tertiary/40"
              >
                <option value="keyword">keyword</option>
                <option value="regex">regex</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">심각도</label>
              <select
                value={editForm.severity}
                onChange={(e) => setEditForm({ ...editForm, severity: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white focus:outline-none focus:border-tertiary/40"
              >
                <option value="critical">긴급 (critical)</option>
                <option value="high">높음 (high)</option>
                <option value="medium">중간 (medium)</option>
                <option value="low">낮음 (low)</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/60 mb-1 block">조치</label>
              <select
                value={editForm.action}
                onChange={(e) => setEditForm({ ...editForm, action: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-sm text-white focus:outline-none focus:border-tertiary/40"
              >
                <option value="block">차단 (block)</option>
                <option value="warn">경고 (warn)</option>
                <option value="log">로깅 (log)</option>
              </select>
            </div>
          </div>
          {editError && <p className="text-xs text-error">{editError}</p>}
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={editSaving}
              className="px-4 py-2 rounded-lg bg-tertiary text-on-primary text-sm font-bold disabled:opacity-50 hover:brightness-110 transition-all"
            >
              {editSaving ? "저장 중…" : "변경 저장"}
            </button>
          </div>
        </form>
      )}

      {/* 정책 목록 */}
      <div className="rounded-xl border border-white/8 overflow-hidden">
        {panelError && (
          <div className="border-b border-error/20 bg-error/8 px-4 py-3 text-xs font-bold text-error">
            {panelError}
          </div>
        )}
        {loading ? (
          <div className="px-6 py-10 flex justify-center">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : policies.length === 0 ? (
          <div className="px-6 py-10 text-center text-on-surface-variant/40 text-sm">
            등록된 정책이 없습니다. "새 정책" 버튼으로 추가하세요.
          </div>
        ) : (
          <table className="w-full text-left">
            <thead className="bg-black/20 text-on-surface-variant text-[10px] uppercase tracking-widest font-extrabold">
              <tr>
                <th className="px-4 py-3 whitespace-nowrap">ID</th>
                <th className="px-4 py-3 whitespace-nowrap">정책 이름</th>
                <th className="px-4 py-3">탐지 패턴</th>
                <th className="px-4 py-3 whitespace-nowrap">타입</th>
                <th className="px-4 py-3 whitespace-nowrap">심각도</th>
                <th className="px-4 py-3 whitespace-nowrap">조치</th>
                <th className="px-4 py-3 whitespace-nowrap">상태</th>
                <th className="px-4 py-3 whitespace-nowrap text-right">관리</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {policies.map((p) => {
                const sev = SEVERITY_META[p.severity] || SEVERITY_META.medium;
                const busy = policyBusy[p.id];
                return (
                  <tr key={p.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3 font-mono text-[10px] text-primary/60">POL-{String(p.id).padStart(3, "0")}</td>
                    <td className="px-4 py-3 text-sm font-bold text-white whitespace-nowrap">{p.rule_name}</td>
                    <td className="px-4 py-3 font-mono text-xs text-on-surface-variant/70 break-all max-w-[280px]">{p.pattern}</td>
                    <td className="px-4 py-3 text-xs text-on-surface-variant/60 font-mono">{p.rule_type}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded"
                        style={{ color: sev.color, background: sev.bg, border: `1px solid ${sev.border}` }}>
                        {sev.label}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-white/70">{ACTION_LABEL[p.action] || p.action}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider ${p.is_active ? "text-tertiary" : "text-on-surface-variant/30"}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${p.is_active ? "bg-tertiary" : "bg-on-surface-variant/30"}`} />
                        {p.is_active ? "활성" : "비활성"}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => openEdit(p)}
                          disabled={Boolean(busy)}
                          className="grid h-7 w-7 place-items-center rounded-lg border border-white/10 bg-white/[0.03] text-on-surface-variant/80 transition-colors hover:bg-white/[0.07] hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
                          aria-label="정책 수정"
                          title="수정"
                        >
                          <span className="material-symbols-outlined text-[15px]">edit</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleToggle(p)}
                          disabled={Boolean(busy)}
                          className={`relative h-7 w-12 rounded-full border transition-all disabled:cursor-not-allowed disabled:opacity-50 ${
                            p.is_active
                              ? "border-primary/40 bg-primary/20"
                              : "border-white/10 bg-black/30"
                          }`}
                          aria-label={p.is_active ? "정책 비활성화" : "정책 활성화"}
                          title={p.is_active ? "비활성화" : "활성화"}
                        >
                          <span
                            className={`absolute top-1 h-5 w-5 rounded-full transition-all ${
                              p.is_active
                                ? "left-6 bg-primary shadow-[0_0_12px_rgba(45,212,191,0.35)]"
                                : "left-1 bg-on-surface-variant/50"
                            }`}
                          />
                          {busy === "toggle" && (
                            <span className="absolute inset-0 grid place-items-center">
                              <span className="h-3 w-3 animate-spin rounded-full border border-white/40 border-t-transparent" />
                            </span>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDelete(p)}
                          disabled={Boolean(busy)}
                          className="grid h-7 w-7 place-items-center rounded-lg border border-error/20 bg-error/8 text-error/80 transition-colors hover:bg-error/15 hover:text-error disabled:cursor-not-allowed disabled:opacity-50"
                          aria-label="정책 삭제"
                          title="삭제"
                        >
                          {busy === "delete" ? (
                            <span className="h-3 w-3 animate-spin rounded-full border border-error/50 border-t-transparent" />
                          ) : (
                            <span className="material-symbols-outlined text-[15px]">delete</span>
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
