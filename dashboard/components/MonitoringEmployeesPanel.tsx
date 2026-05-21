"use client";

import { useState, useEffect, useCallback } from "react";
import { getEmployees, Employee } from "../lib/api";

export default function MonitoringEmployeesPanel() {
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const e = await getEmployees();
      setEmployees(e);
    } catch {
      setEmployees([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-lg font-bold text-white">모니터링 대상 직원</h3>
          <span className="text-[10px] font-bold uppercase tracking-widest text-tertiary bg-tertiary/10 border border-tertiary/20 px-2 py-0.5 rounded">
            Total {employees.length}
          </span>
        </div>
        <p className="text-[10px] text-on-surface-variant/40 leading-relaxed">
          1:1 챗봇을 처음 사용하면 로그인 계정이 자동 등록됩니다.
        </p>
      </div>

      <div className="rounded-xl border border-white/8 overflow-hidden">
        {loading ? (
          <div className="px-6 py-10 flex justify-center">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : employees.length === 0 ? (
          <div className="px-6 py-10 text-center text-on-surface-variant/40 text-sm">
            등록된 직원이 없습니다. 1:1 챗봇 첫 사용 시 자동 등록됩니다.
          </div>
        ) : (
          <table className="w-full text-left">
            <thead className="bg-black/20 text-on-surface-variant text-[10px] uppercase tracking-widest font-extrabold">
              <tr>
                <th className="px-4 py-3 whitespace-nowrap">Employee ID</th>
                <th className="px-4 py-3 whitespace-nowrap">이름</th>
                <th className="px-4 py-3 whitespace-nowrap">부서</th>
                <th className="px-4 py-3 whitespace-nowrap">역할</th>
                <th className="px-4 py-3 whitespace-nowrap">상태</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {employees.map((e) => (
                <tr key={e.id} className="hover:bg-white/[0.02] transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-primary/70">{e.employee_id}</td>
                  <td className="px-4 py-3 text-sm font-bold text-white whitespace-nowrap">{e.name}</td>
                  <td className="px-4 py-3 text-xs text-on-surface-variant/70">{e.department}</td>
                  <td className="px-4 py-3 text-xs text-on-surface-variant/70">{e.role}</td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className={`inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider ${
                      e.status === "active" ? "text-tertiary" : "text-on-surface-variant/40"
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${e.status === "active" ? "bg-tertiary" : "bg-on-surface-variant/40"}`} />
                      {e.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
