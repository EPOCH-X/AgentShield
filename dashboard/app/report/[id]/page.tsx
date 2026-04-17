"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import DashboardLayout from "../../../components/DashboardLayout";
import { getToken } from "../../../lib/api";

export default function ReportPage({ params }: { params: { id: string } }) {
  const router = useRouter();
  const sessionId = params.id;
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState("");

  async function handleDownload() {
    setDownloading(true);
    setError("");
    try {
      const token = getToken();
      const res = await fetch(`/api/v1/report/${sessionId}/pdf`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });

      if (!res.ok) {
        throw new Error("PDF를 생성할 수 없습니다. 스캔이 완료되었는지 확인해 주세요.");
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `agentshield-report-${sessionId.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "PDF 다운로드에 실패했습니다.");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <DashboardLayout>
      <div className="p-10 max-w-4xl mx-auto space-y-8">
        {/* 헤더 */}
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-[0.2em]">
              <span className="w-8 h-px bg-primary" />
              Security Report
            </div>
            <h2 className="text-4xl font-headline font-extrabold tracking-tight text-white">
              스캔 보고서
            </h2>
            <p className="font-mono text-sm text-on-surface-variant">
              Session: <span className="text-primary">{sessionId}</span>
            </p>
          </div>
          <button
            onClick={() => router.push(`/scan/${sessionId}`)}
            className="flex items-center gap-2 px-5 py-3 rounded-2xl bg-white/5 border border-white/10 text-on-surface-variant hover:text-white hover:border-primary/30 transition-all font-medium text-sm"
          >
            <span className="material-symbols-outlined text-lg">arrow_back</span>
            스캔 결과로 돌아가기
          </button>
        </div>

        {/* PDF 다운로드 카드 */}
        <div className="glass-panel rounded-[2rem] p-10 flex flex-col items-center gap-8 shadow-2xl text-center">
          <div className="w-24 h-24 rounded-[2rem] bg-gradient-to-br from-primary/20 to-primary-container/20 border border-primary/20 flex items-center justify-center neon-glow-primary">
            <span
              className="material-symbols-outlined text-primary text-5xl"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              picture_as_pdf
            </span>
          </div>

          <div className="space-y-3">
            <h3 className="text-2xl font-black font-headline text-white">
              AgentShield 취약점 분석 보고서
            </h3>
            <p className="text-on-surface-variant max-w-md text-sm leading-relaxed">
              스캔 세션의 전체 취약점 분석 결과, 공격 패턴, 방어 코드 제안 및 검증 결과를
              포함한 PDF 보고서를 다운로드합니다.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-6 w-full max-w-md">
            {[
              { icon: "bug_report", label: "취약점 상세", color: "text-error" },
              { icon: "shield", label: "방어 코드", color: "text-primary" },
              { icon: "verified_user", label: "검증 결과", color: "text-tertiary" },
            ].map((item) => (
              <div
                key={item.label}
                className="p-4 rounded-2xl bg-white/3 border border-white/5 flex flex-col items-center gap-2"
              >
                <span className={`material-symbols-outlined ${item.color}`}>{item.icon}</span>
                <p className="text-[10px] text-on-surface-variant font-bold uppercase tracking-wider">
                  {item.label}
                </p>
              </div>
            ))}
          </div>

          {error && (
            <div className="w-full flex items-center gap-3 p-4 rounded-2xl bg-error/10 border border-error/20">
              <span className="material-symbols-outlined text-error">error</span>
              <p className="text-sm text-error">{error}</p>
            </div>
          )}

          <button
            onClick={handleDownload}
            disabled={downloading}
            className="px-10 py-5 rounded-[1.25rem] bg-gradient-to-r from-primary via-[#57FF35] to-primary-container text-on-primary font-extrabold text-sm tracking-[0.1em] uppercase shadow-[0_10px_30px_rgba(57,255,20,0.3)] hover:shadow-[0_15px_40px_rgba(57,255,20,0.45)] hover:-translate-y-0.5 transition-all active:scale-[0.98] neon-glow-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {downloading ? (
              <span className="flex items-center gap-2">
                <span className="w-4 h-4 border-2 border-on-primary border-t-transparent rounded-full animate-spin" />
                PDF 생성 중...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <span className="material-symbols-outlined text-lg">download</span>
                PDF 보고서 다운로드
              </span>
            )}
          </button>
        </div>

        {/* 보고서 내용 미리보기 안내 */}
        <div className="bg-primary/5 p-6 rounded-2xl border-l-4 border-primary/60 flex items-start gap-4">
          <span
            className="material-symbols-outlined text-primary neon-glow-primary"
            style={{ fontVariationSettings: "'FILL' 1" }}
          >
            info
          </span>
          <div className="space-y-1">
            <p className="text-xs font-bold text-on-surface uppercase tracking-wider">
              보고서 포함 내용
            </p>
            <ul className="text-[11px] text-on-surface-variant leading-relaxed font-medium space-y-1">
              <li>• 스캔 개요: 대상 URL, 프로젝트 이름, 시작/종료 시간</li>
              <li>• Phase 1-4 각 단계별 테스트 결과 요약</li>
              <li>• 발견된 취약점 목록 및 심각도 분류 (OWASP LLM Top 10)</li>
              <li>• Blue Agent가 생성한 방어 코드 제안</li>
              <li>• Phase 4 검증 결과 (차단율, 우회율, 위양성율)</li>
            </ul>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
