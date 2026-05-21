"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import DashboardLayout from "../../../components/DashboardLayout";
import {
  getLatestScan,
  getScanStatus,
  getScanResults,
  getPolicyPackage,
  getOwaspGuidance,
  downloadAuthenticated,
  ScanResult,
  PolicyPackageBundle,
  OwaspGuidanceBundle,
} from "../../../lib/api";

type ReportStatus = {
  session_id: string;
  status: string;
  phase?: number;
  total_tests?: number;
  completed_tests?: number;
  vulnerable_count?: number;
  safe_count?: number;
  elapsed_seconds?: number;
};

type DemoReportSnapshot = {
  status: ReportStatus;
  results: ScanResult[];
};

const DEMO_REPORT_STORAGE_KEY = "agentshield_demo_report_snapshot";
const DEMO_RESTORE_FLAG_KEY = "agentshield_demo_restore_requested";

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

// 카테고리별 조치 가이드는 backend API(/api/v1/policy-export/guidance)에서 로드한다.
// 원본은 data/owasp_guidance.yaml — 코드 안 하드코딩 ×, 보안팀이 yaml로 관리.

function fmtElapsed(s: number) {
  return `${Math.floor(s / 60)}분 ${s % 60}초`;
}

// AgentShield 공격 카탈로그(자산)의 페이로드를 고객 리포트에 그대로 노출하지 않기 위한 부분 마스킹.
// 카테고리/기법은 보이게 두고, 민감 패턴(키·토큰·PII)·긴 인코딩 블록만 가린다.
function maskAttackPayload(text: string): string {
  if (!text) return text;
  return text
    // sk-/pk-/api-key 류 토큰
    .replace(/\b((?:sk|pk|rk|api[-_]?key|token|bearer)[-_]?[A-Za-z0-9]{2,4})[A-Za-z0-9_\-]{8,}/gi,
      (_m, head) => `${head}▓▓▓▓▓▓`)
    // 32자 이상 영숫자/하이픈 토큰
    .replace(/\b[A-Za-z0-9_\-]{32,}\b/g, (m) => `${m.slice(0, 4)}▓▓▓▓(${m.length}자)`)
    // 이메일: 앞 2자만 노출
    .replace(/\b([A-Za-z0-9._%+\-]{1,2})[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b/g,
      (_m, p1, p2) => `${p1}***@${p2}`)
    // 신용카드/긴 숫자열
    .replace(/\b\d{12,19}\b/g, (m) => `${m.slice(0, 4)}-▓▓▓▓-▓▓▓▓-${m.slice(-4)}`);
}

export default function ReportPage({ params }: { params: { id: string } }) {
  const router    = useRouter();
  const sessionId = params.id;

  const [status,  setStatus]  = useState<ReportStatus | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [openSet, setOpenSet] = useState<Set<number>>(new Set());
  const [policyPkg, setPolicyPkg] = useState<PolicyPackageBundle | null>(null);
  const [guidance, setGuidance] = useState<OwaspGuidanceBundle | null>(null);

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError("");
      try {
        const rawSnapshot = localStorage.getItem(DEMO_REPORT_STORAGE_KEY);
        const snapshot = rawSnapshot ? JSON.parse(rawSnapshot) as DemoReportSnapshot : null;
        if (snapshot?.status?.session_id === sessionId) {
          const orderedResults = [...(snapshot.results || [])].sort((a, b) => {
            const priority = (result: ScanResult) =>
              result.phase === 2 && result.judgment === "vulnerable" ? 0 :
              result.phase === 2 ? 1 :
              2;
            return priority(a) - priority(b);
          });
          setStatus(snapshot.status);
          setResults(orderedResults);
          return;
        }
        if (sessionId === "latest") {
          const latest = await getLatestScan();
          router.replace(`/report/${latest.session_id}`);
          return;
        }
        const [s, r] = await Promise.all([
          getScanStatus(sessionId),
          getScanResults(sessionId),
        ]);
        setStatus(s);
        // Phase 4(재검증 로그)는 별도 row지만 사용자가 봐야 할 정보는 Phase 1/2 카드의 AFTER 패널에
        // verify_result로 이미 합쳐서 표시된다. 카드 목록은 vulnerable/safe 본 결과만 노출.
        setResults(r.filter((row) => row.phase !== 4));
        // 정책 패키지는 있으면 가져오고, 없으면 무시
        try {
          const pkg = await getPolicyPackage(sessionId);
          setPolicyPkg(pkg);
        } catch {
          setPolicyPkg(null);
        }
        // OWASP 가이드 (yaml 단일 소스)
        try {
          const g = await getOwaspGuidance();
          setGuidance(g);
        } catch {
          setGuidance(null);
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "리포트 데이터를 가져올 수 없습니다.");
        setStatus(null);
        setResults([]);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [router, sessionId]);

  function toggleCard(id: number) {
    setOpenSet((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function goBack() {
    const rawSnapshot = localStorage.getItem(DEMO_REPORT_STORAGE_KEY);
    const snapshotSessionId = rawSnapshot ? (JSON.parse(rawSnapshot) as DemoReportSnapshot)?.status?.session_id : "";
    if (snapshotSessionId === sessionId) {
      sessionStorage.setItem(DEMO_RESTORE_FLAG_KEY, "1");
      router.push("/demo");
      return;
    }
    router.push(`/scan/${sessionId}`);
  }

  const total      = results.length;
  const vulnerable = results.filter((r) => r.judgment === "vulnerable").length;
  const safe       = results.filter((r) => r.judgment === "safe").length;
  const reviewCount = results.filter((r) => !["safe", "vulnerable"].includes(String(r.judgment))).length;

  function resultKind(result: ScanResult) {
    if (result.judgment === "vulnerable") {
      return { label: "취약점", icon: "gpp_bad" };
    }
    if (result.judgment === "safe") {
      return { label: "안전 항목", icon: "verified_user" };
    }
    return { label: "검토 항목", icon: "rule" };
  }

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
              onClick={goBack}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-on-surface-variant hover:text-white hover:border-primary/30 transition-all font-medium text-sm"
            >
              <span className="material-symbols-outlined text-base">arrow_back</span>
              돌아가기
            </button>
          </div>
        </div>

        {/* Phase 5 정책 패키지 상태 — 취약점이 없어도 상태 박스는 항상 표시 */}
        {!policyPkg && (
          <div className="anim-fade-up rounded-2xl border overflow-hidden"
            style={{ background: "rgba(14,165,165,0.055)", borderColor: "rgba(14,165,165,0.22)", animationDelay: "80ms" }}>
            <div className="flex items-center gap-2.5 px-5 py-3.5"
              style={{ background: "rgba(14,165,165,0.08)", borderBottom: "1px solid rgba(14,165,165,0.16)" }}>
              <span className="material-symbols-outlined text-base" style={{ color: "#5eead4", fontVariationSettings: "'FILL' 1" }}>policy</span>
              <p className="text-xs font-black uppercase tracking-widest" style={{ color: "#99f6e4" }}>
                Phase 5 · Guardrail Policy Package
              </p>
              <span className="ml-auto text-[10px] text-white/30 font-mono">SESSION {sessionId.slice(0, 8).toUpperCase()}</span>
            </div>

            <div className="grid grid-cols-3 gap-3 p-4">
              <div className="rounded-xl px-4 py-3 border" style={{ background: "rgba(0,0,0,0.3)", borderColor: "rgba(14,165,165,0.18)" }}>
                <p className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-1">패키지 상태</p>
                <p className="text-base font-black text-tertiary">
                  {vulnerable > 0 ? "생성 대기" : "생성 대상 없음"}
                </p>
              </div>
              <div className="rounded-xl px-4 py-3 border" style={{ background: "rgba(0,0,0,0.3)", borderColor: "rgba(14,165,165,0.18)" }}>
                <p className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-1">조치 대상 Findings</p>
                <p className="text-base font-black text-white">
                  {vulnerable}<span className="text-white/30 text-sm font-medium ml-1">/ {total}</span>
                </p>
              </div>
              <div className="rounded-xl px-4 py-3 border" style={{ background: "rgba(0,0,0,0.3)", borderColor: "rgba(14,165,165,0.18)" }}>
                <p className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-1">검토 필요</p>
                <p className="text-base font-black text-white">
                  {reviewCount}<span className="text-white/30 text-sm font-medium ml-1">건</span>
                </p>
              </div>
            </div>

            <div className="px-5 pb-4 text-xs leading-relaxed text-white/50">
              {vulnerable > 0
                ? "취약 결과가 있지만 Phase 5 정책 패키지가 아직 생성되지 않았습니다. 스캔 완료 후 자동 생성 로그 또는 policy-export 엔드포인트를 확인하세요."
                : "취약 판정이 없어 별도 가드레일 정책 패키지와 회귀 테스트 파일은 생성하지 않습니다. 아래 목록은 발견된 취약점이 아니라 테스트된 카테고리별 안전 결과입니다."}
            </div>
          </div>
        )}

        {/* 정책 패키지 패널 — Actionable Evidence */}
        {policyPkg && (
          <div className="anim-fade-up rounded-2xl border overflow-hidden"
            style={{ background: "rgba(124,58,237,0.06)", borderColor: "rgba(124,58,237,0.25)", animationDelay: "80ms" }}>

            {/* 헤더 */}
            <div className="flex items-center gap-2.5 px-5 py-3.5"
              style={{ background: "rgba(124,58,237,0.08)", borderBottom: "1px solid rgba(124,58,237,0.18)" }}>
              <span className="material-symbols-outlined text-base" style={{ color: "#a78bfa", fontVariationSettings: "'FILL' 1" }}>policy</span>
              <p className="text-xs font-black uppercase tracking-widest" style={{ color: "#c4b5fd" }}>
                Actionable Evidence · 조치 가능한 보안 증거
              </p>
              <span className="ml-auto text-[10px] text-white/30 font-mono">SESSION {sessionId.slice(0, 8).toUpperCase()}</span>
            </div>

            {/* Stat 3-col */}
            <div className="grid grid-cols-3 gap-3 p-4">
              <div className="rounded-xl px-4 py-3 border" style={{ background: "rgba(0,0,0,0.3)", borderColor: "rgba(124,58,237,0.18)" }}>
                <p className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-1">패키지 상태</p>
                <p className="text-base font-black" style={{
                  color: policyPkg.manifest.package_status === "validated" ? "#5eead4" :
                         policyPkg.manifest.package_status === "empty" ? "#fbbf24" : "#ef4444"
                }}>
                  {policyPkg.manifest.package_status === "validated" ? "검증 완료" :
                   policyPkg.manifest.package_status === "empty" ? "검증 대상 없음" : "검증 실패"}
                </p>
              </div>
              <div className="rounded-xl px-4 py-3 border" style={{ background: "rgba(0,0,0,0.3)", borderColor: "rgba(124,58,237,0.18)" }}>
                <p className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-1">검증된 Findings</p>
                <p className="text-base font-black text-white">
                  {policyPkg.manifest.verified_safe_count}
                  <span className="text-white/30 text-sm font-medium ml-1">/ {policyPkg.manifest.total_findings}</span>
                </p>
              </div>
              <div className="rounded-xl px-4 py-3 border" style={{ background: "rgba(0,0,0,0.3)", borderColor: "rgba(124,58,237,0.18)" }}>
                <p className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-1">회귀 테스트</p>
                <p className="text-base font-black text-white">
                  {policyPkg.regression_tests?.length ?? 0}<span className="text-white/30 text-sm font-medium ml-1">건</span>
                </p>
              </div>
            </div>

            {/* 다운로드 버튼 row */}
            {(policyPkg.reports || policyPkg.download_url) && (() => {
              const dl = (path: string | null | undefined, filename: string) => {
                if (!path) return;
                void downloadAuthenticated(path, filename).catch((err) => alert(err.message || "다운로드 실패"));
              };
              const execPdf  = policyPkg.reports?.executive_summary_pdf;
              const execHtml = policyPkg.reports?.executive_summary_html;
              const fullPdf  = policyPkg.reports?.full_report_pdf;
              const fullHtml = policyPkg.reports?.full_report_html;
              const zip      = policyPkg.download_url;
              const sid8 = sessionId.slice(0, 8);
              return (
                <div className="px-4 pb-4">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-2 px-1">외부 공유 산출물 · 다운로드</p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {/* 경영진 요약 */}
                    <button
                      onClick={() => dl(execPdf || execHtml, `agentshield-${sid8}-executive_summary.${execPdf ? "pdf" : "html"}`)}
                      disabled={!execPdf && !execHtml}
                      className="flex items-center gap-3 px-4 py-3 rounded-xl border text-left transition-all hover:brightness-125 disabled:opacity-30 disabled:cursor-not-allowed"
                      style={{ background: execPdf ? "rgba(239,68,68,0.12)" : "rgba(59,130,246,0.12)",
                               borderColor: execPdf ? "rgba(239,68,68,0.35)" : "rgba(59,130,246,0.35)" }}>
                      <span className="material-symbols-outlined text-2xl shrink-0" style={{ color: execPdf ? "#fca5a5" : "#93c5fd", fontVariationSettings: "'FILL' 1" }}>
                        {execPdf ? "picture_as_pdf" : "description"}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-bold text-white">경영진 요약</div>
                        <div className="text-[10px] text-white/45 font-mono">{execPdf ? "PDF" : "HTML"} · A4 1–2장</div>
                      </div>
                      <span className="material-symbols-outlined text-base text-white/40">download</span>
                    </button>

                    {/* 상세 보고서 */}
                    <button
                      onClick={() => dl(fullPdf || fullHtml, `agentshield-${sid8}-full_report.${fullPdf ? "pdf" : "html"}`)}
                      disabled={!fullPdf && !fullHtml}
                      className="flex items-center gap-3 px-4 py-3 rounded-xl border text-left transition-all hover:brightness-125 disabled:opacity-30 disabled:cursor-not-allowed"
                      style={{ background: fullPdf ? "rgba(239,68,68,0.12)" : "rgba(59,130,246,0.12)",
                               borderColor: fullPdf ? "rgba(239,68,68,0.35)" : "rgba(59,130,246,0.35)" }}>
                      <span className="material-symbols-outlined text-2xl shrink-0" style={{ color: fullPdf ? "#fca5a5" : "#93c5fd", fontVariationSettings: "'FILL' 1" }}>
                        {fullPdf ? "picture_as_pdf" : "description"}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-bold text-white">상세 보고서</div>
                        <div className="text-[10px] text-white/45 font-mono">{fullPdf ? "PDF" : "HTML"} · 카드 long-form</div>
                      </div>
                      <span className="material-symbols-outlined text-base text-white/40">download</span>
                    </button>

                    {/* 정책 패키지 ZIP */}
                    <button
                      onClick={() => dl(zip, `agentshield-${sid8}-policy_package.zip`)}
                      disabled={!zip}
                      className="flex items-center gap-3 px-4 py-3 rounded-xl border text-left transition-all hover:brightness-125 disabled:opacity-30 disabled:cursor-not-allowed"
                      style={{ background: "rgba(124,58,237,0.15)", borderColor: "rgba(124,58,237,0.35)" }}>
                      <span className="material-symbols-outlined text-2xl shrink-0" style={{ color: "#c4b5fd", fontVariationSettings: "'FILL' 1" }}>folder_zip</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-bold text-white">정책 패키지</div>
                        <div className="text-[10px] text-white/45 font-mono">ZIP · 미들웨어/회귀 테스트 등 9 파일</div>
                      </div>
                      <span className="material-symbols-outlined text-base text-white/40">download</span>
                    </button>
                  </div>
                  {!execPdf && !fullPdf && (
                    <p className="text-[10px] text-white/35 mt-2 px-1">
                      PDF가 비활성화된 상태입니다. <code className="text-white/55">brew install pango && pip install weasyprint</code> 설치 후 다음 스캔부터 PDF가 자동 생성됩니다.
                    </p>
                  )}
                </div>
              );
            })()}

            {/* OWASP 매핑 row */}
            {policyPkg.middleware_policy?.category_actions && Object.keys(policyPkg.middleware_policy.category_actions).length > 0 && (
              <div className="px-5 py-4" style={{ borderTop: "1px solid rgba(124,58,237,0.15)" }}>
                <div className="flex items-center gap-2 mb-2 flex-wrap">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-white/40">미들웨어 정책 · 카테고리별 권장 액션</p>
                  <span className="text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded"
                    style={{ color: "#fbbf24", background: "rgba(251,191,36,0.08)", border: "1px solid rgba(251,191,36,0.22)" }}>
                    OWASP LLM Top 10 v1.1 기반
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(policyPkg.middleware_policy.category_actions).map(([cat, action]) => (
                    <span key={cat} className="px-2.5 py-1 rounded-md text-[11px] font-bold border"
                      style={{ background: "rgba(0,0,0,0.3)", borderColor: "rgba(124,58,237,0.25)", color: "#c4b5fd" }}>
                      <span className="text-white/80">{cat}</span>
                      <span className="text-white/30 mx-1.5">→</span>
                      <span>{action}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── 카드 목록 ── */}
        {results.length === 0 ? (
          <div className="glass-panel rounded-2xl py-20 text-center text-on-surface-variant/40 text-sm">
            {error || "결과 없음"}
          </div>
        ) : (
          <div className="space-y-6">
            {results.map((r, i) => {
              const sev     = SEVERITY_CFG[r.severity as keyof typeof SEVERITY_CFG] ?? SEVERITY_CFG.medium;
              const catMeta = CATEGORY_META[r.category];
              const isVuln  = r.judgment === "vulnerable";
              const kind    = resultKind(r);
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
                        {kind.label} {String(i + 1).padStart(2, "0")}
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
                            {kind.icon}
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

                        {/* ① 공격 프롬프트 원문 */}
                        {r.attack_prompt && (
                          <div className="px-7 py-5"
                            style={{ background: "rgba(239,68,68,0.06)", borderBottom: "1px solid rgba(239,68,68,0.15)" }}>
                            <div className="flex items-center gap-2 mb-3">
                              <span className="material-symbols-outlined text-base" style={{ color: "#ef4444", fontVariationSettings: "'FILL' 1" }}>code</span>
                              <p className="text-xs font-bold uppercase tracking-widest" style={{ color: "#ef4444cc" }}>
                                공격 프롬프트 원문
                              </p>
                              <span className="text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded"
                                style={{ color: "#fbbf24", background: "rgba(251,191,36,0.10)", border: "1px solid rgba(251,191,36,0.25)" }}
                                title="AgentShield 공격 카탈로그(자산) 보호 — 페이로드 일부는 마스킹되어 표시됩니다.">
                                AgentShield 자산 · 부분 마스킹
                              </span>
                            </div>
                            <pre className="font-mono text-sm text-white/85 leading-relaxed whitespace-pre-wrap break-words rounded-lg p-4 overflow-y-auto"
                              style={{ background: "rgba(0,0,0,0.35)", border: "1px solid rgba(239,68,68,0.18)", maxHeight: "320px" }}>
                              {maskAttackPayload(r.attack_prompt)}
                            </pre>
                          </div>
                        )}

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

                        {/* ③ 비교 배너 */}
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

                        {/* ④ BEFORE / AFTER */}
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
                                  <pre className="font-mono text-sm font-semibold text-error/90 leading-relaxed whitespace-pre-wrap break-words overflow-y-auto"
                                    style={{ maxHeight: "180px" }}>
                                    {r.danger_highlight}
                                  </pre>
                                </div>
                              )}
                              <div>
                                <p className="text-[10px] font-bold uppercase tracking-widest text-white/30 mb-1.5">AI 응답 전문</p>
                                {r.target_response ? (
                                  <pre className="font-mono text-xs text-white/70 leading-relaxed whitespace-pre-wrap break-words rounded-lg p-3 overflow-y-auto"
                                    style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)", maxHeight: "420px" }}>
                                    {r.target_response}
                                  </pre>
                                ) : (
                                  <p className="text-xs text-white/20 italic">응답 없음</p>
                                )}
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
                            <div className="p-6 space-y-4">
                              {r.defended_response ? (
                                <div className="rounded-xl p-4 safe-pulse"
                                  style={{ background: "rgba(14,165,165,0.09)", border: "1.5px solid rgba(14,165,165,0.3)" }}>
                                  <p className="text-[11px] font-black text-primary uppercase tracking-widest mb-2.5">✓ 방어된 AI 응답</p>
                                  <pre className="font-mono text-xs leading-relaxed whitespace-pre-wrap break-words overflow-y-auto"
                                    style={{ color: "#5eead4ee", maxHeight: "420px" }}>
                                    {r.defended_response}
                                  </pre>
                                </div>
                              ) : (
                                <p className="text-xs text-white/20 italic">방어 응답 미생성</p>
                              )}

                              {r.defense_rationale && (
                                <div>
                                  <p className="text-[10px] font-bold uppercase tracking-widest text-white/30 mb-1.5">Blue Agent · 방어 근거</p>
                                  <p className="text-xs text-white/55 leading-relaxed whitespace-pre-wrap break-words rounded-lg p-3 overflow-y-auto"
                                    style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)", maxHeight: "240px" }}>
                                    {r.defense_rationale}
                                  </p>
                                </div>
                              )}

                              {r.verify_result && (
                                <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest">
                                  <span className="material-symbols-outlined text-sm text-primary" style={{ fontVariationSettings: "'FILL' 1" }}>fact_check</span>
                                  <span className="text-white/40">검증 결과 ·</span>
                                  <span style={{ color: r.verify_result === "safe" ? "#5eead4" : r.verify_result === "vulnerable" ? "#ef4444" : "#fbbf24" }}>
                                    {r.verify_result}
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>

                        </div>

                        {/* ⑤ 조치 항목 — 어디를 고쳐야 하는지 */}
                        {(() => {
                          const guide = guidance?.categories?.[r.category];
                          const refusal = policyPkg?.refusal_templates?.find((t) => t.category === r.category);
                          const regression = policyPkg?.regression_tests?.find((t) => t.source_result_id === r.id);
                          if (!guide && !refusal && !regression) return null;
                          return (
                            <div className="px-7 py-5"
                              style={{ background: "rgba(124,58,237,0.05)", borderTop: "1px solid rgba(124,58,237,0.18)" }}>
                              <div className="flex items-center gap-2 mb-3">
                                <span className="material-symbols-outlined text-base" style={{ color: "#a78bfa", fontVariationSettings: "'FILL' 1" }}>policy</span>
                                <p className="text-xs font-black uppercase tracking-widest" style={{ color: "#c4b5fd" }}>조치 항목 · Action Items</p>
                              </div>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                {guide && (
                                  <div className="rounded-lg p-3 border" style={{ background: "rgba(0,0,0,0.28)", borderColor: "rgba(124,58,237,0.2)" }}>
                                    <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
                                      <p className="text-[10px] font-bold uppercase tracking-widest text-white/40">권장 액션</p>
                                      <a
                                        href={guide.reference_url}
                                        target="_blank"
                                        rel="noreferrer"
                                        className="text-[9px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded hover:brightness-125"
                                        style={{ color: "#fbbf24", background: "rgba(251,191,36,0.08)", border: "1px solid rgba(251,191,36,0.22)" }}
                                        title={`${r.category} ${guide.name} — ${guidance?.source}`}>
                                        OWASP 권고 ↗
                                      </a>
                                    </div>
                                    <p className="text-sm font-bold text-white mb-2">
                                      {guide.action_label_ko} <span className="text-white/30 font-mono text-xs">({guide.default_action})</span>
                                    </p>
                                    <p className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-1.5">고쳐야 할 지점 <span className="text-white/25 normal-case font-normal">(고객사 환경 맞춤화 필요)</span></p>
                                    <ul className="space-y-1">
                                      {guide.fix_targets.map((target: string) => (
                                        <li key={target} className="text-xs text-white/70 flex items-start gap-2">
                                          <span className="text-white/30 font-bold">·</span>
                                          <span>{target}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                <div className="space-y-3">
                                  {refusal && (
                                    <div className="rounded-lg p-3 border" style={{ background: "rgba(0,0,0,0.28)", borderColor: "rgba(124,58,237,0.2)" }}>
                                      <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
                                        <p className="text-[10px] font-bold uppercase tracking-widest text-white/40">Refusal Template</p>
                                        <span className="text-[9px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded"
                                          style={{ color: "#5eead4", background: "rgba(14,165,165,0.10)", border: "1px solid rgba(14,165,165,0.25)" }}>
                                          본 스캔 검증 데이터
                                        </span>
                                      </div>
                                      <pre className="text-xs text-white/75 leading-relaxed whitespace-pre-wrap break-words font-mono overflow-y-auto" style={{ maxHeight: "120px" }}>
                                        {refusal.template}
                                      </pre>
                                    </div>
                                  )}
                                  {regression && (
                                    <div className="rounded-lg p-3 border" style={{ background: "rgba(0,0,0,0.28)", borderColor: "rgba(124,58,237,0.2)" }}>
                                      <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
                                        <p className="text-[10px] font-bold uppercase tracking-widest text-white/40">회귀 테스트</p>
                                        <span className="text-[9px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded"
                                          style={{ color: "#5eead4", background: "rgba(14,165,165,0.10)", border: "1px solid rgba(14,165,165,0.25)" }}>
                                          본 스캔 검증 데이터
                                        </span>
                                      </div>
                                      <p className="text-xs text-white/75 font-mono break-all">{regression.test_id}</p>
                                      <p className="text-[10px] text-white/40 mt-1">expected: <span className="text-white/60 font-bold">{regression.expected_action}</span></p>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          );
                        })()}
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
