"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import DashboardLayout from "../../components/DashboardLayout";
import { startScan } from "../../lib/api";

const MOCK_SESSION_ID = "mock-session-demo";

const ATTACK_VECTORS = [
  { id: "jailbreak", icon: "gavel", label: "탈옥 (Jailbreak)", fill: true },
  { id: "data_leak", icon: "data_loss_prevention", label: "데이터 유출", fill: false },
  { id: "prompt_injection", icon: "terminal", label: "프롬프트 주입", fill: true },
  { id: "harmful_output", icon: "block", label: "유해한 출력", fill: false },
];

interface RecentScan {
  session_id: string;
  project_name: string;
  target_api_url: string;
  status: string;
  created_at: string;
}

function statusMeta(status: string) {
  const map: Record<string, { cls: string; dot: string; label: string; icon: string }> = {
    completed: {
      cls: "bg-tertiary/10 text-tertiary border-tertiary/20",
      dot: "bg-tertiary",
      label: "완료",
      icon: "check_circle",
    },
    running: {
      cls: "bg-primary/10 text-primary border-primary/20",
      dot: "bg-primary animate-pulse",
      label: "실행 중",
      icon: "radar",
    },
    failed: {
      cls: "bg-error/10 text-error border-error/20",
      dot: "bg-error",
      label: "실패",
      icon: "error",
    },
    pending: {
      cls: "bg-outline/10 text-outline border-outline/20",
      dot: "bg-outline",
      label: "대기",
      icon: "schedule",
    },
  };
  return map[status] || map.pending;
}

export default function ScanPage() {
  const router = useRouter();
  const [projectName, setProjectName] = useState("Enterprise-LLM-Production");
  const [targetUrl, setTargetUrl] = useState("https://api.internal.llm/v1/chat");
  const [targetApiKey, setTargetApiKey] = useState("");
  const [selectedVectors, setSelectedVectors] = useState<string[]>(["jailbreak", "prompt_injection"]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);

  useEffect(() => {
    try {
      const stored = localStorage.getItem("recent_scans");
      if (stored) setRecentScans(JSON.parse(stored));
    } catch {
      // ignore
    }
  }, []);

  function toggleVector(id: string) {
    setSelectedVectors((prev) => {
      if (prev.includes(id)) {
        if (prev.length <= 1) return prev;
        return prev.filter((v) => v !== id);
      }
      return [...prev, id];
    });
  }

  async function handleStartScan(e: React.FormEvent) {
    e.preventDefault();
    if (!targetUrl.trim() || !projectName.trim()) {
      setError("프로젝트 이름과 대상 URL을 입력해 주세요.");
      return;
    }
    if (selectedVectors.length === 0) {
      setError("공격 벡터는 최소 1개 이상 선택해 주세요.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      let data: { session_id: string; status: string };
      try {
        data = await startScan(targetUrl.trim(), projectName.trim(), targetApiKey.trim() || undefined, "auto");
      } catch {
        data = { session_id: MOCK_SESSION_ID, status: "running" };
      }
      const newScan: RecentScan = {
        session_id: data.session_id,
        project_name: projectName,
        target_api_url: targetUrl,
        status: data.status,
        created_at: new Date().toISOString(),
      };
      const updated = [newScan, ...recentScans].slice(0, 10);
      localStorage.setItem("recent_scans", JSON.stringify(updated));
      router.push(`/scan/${data.session_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "스캔을 시작할 수 없습니다.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <DashboardLayout>
      <div className="p-10 max-w-[1700px] mx-auto w-full space-y-10 page-fade-in">

        {/* ─── 헤더 ─── */}
        <div className="flex items-end justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest">
              <span className="material-symbols-outlined text-xs">shield</span>
              ADVERSARIAL TESTING
            </div>
            <h2 className="text-4xl font-extrabold tracking-tight font-headline text-on-surface">
              LLM 취약점 스캔
            </h2>
            <p className="text-on-surface-variant/80 text-sm">
              심층 적대적 테스트로 LLM 엔드포인트의 취약점을 분석합니다.{" "}
              <Link href="/overview" className="text-primary/90 hover:text-primary font-bold hover:underline underline-offset-2">
                플랫폼 개요
              </Link>
            </p>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-on-surface-variant/60 font-mono">
            <span className="w-2 h-2 rounded-full bg-tertiary animate-pulse" />
            SYSTEM READY
          </div>
        </div>

        {/* ─── 스캔 시작 폼 (전체 폭) ─── */}
        <form onSubmit={handleStartScan}>
          <div className="glass-panel rounded-[2rem] p-8 shadow-2xl relative overflow-hidden">
            {/* 배경 글로우 */}
            <div className="absolute -top-32 -right-32 w-64 h-64 bg-primary/5 rounded-full blur-3xl pointer-events-none" />
            <div className="absolute -bottom-20 -left-20 w-48 h-48 bg-secondary/5 rounded-full blur-3xl pointer-events-none" />

            <div className="relative z-10 space-y-7">
              {/* 입력 필드 행 */}
              <div className="grid grid-cols-12 gap-5">
                {/* 프로젝트 이름 */}
                <div className="col-span-12 md:col-span-3 space-y-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    프로젝트 이름
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      value={projectName}
                      onChange={(e) => setProjectName(e.target.value)}
                      placeholder="프로젝트 이름"
                      className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-3.5 text-sm focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all"
                    />
                  </div>
                </div>

                {/* 대상 URL */}
                <div className="col-span-12 md:col-span-4 space-y-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    대상 API 엔드포인트
                  </label>
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-primary/60 text-lg">api</span>
                    <input
                      type="text"
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="https://..."
                      className="w-full bg-white/5 border border-white/10 rounded-2xl pl-12 pr-5 py-3.5 text-sm font-mono focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all"
                    />
                  </div>
                </div>

                {/* API 키 */}
                <div className="col-span-12 md:col-span-3 space-y-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    API Key <span className="normal-case text-outline">(선택)</span>
                  </label>
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-primary/60 text-lg">key</span>
                    <input
                      type="password"
                      value={targetApiKey}
                      onChange={(e) => setTargetApiKey(e.target.value)}
                      placeholder="Bearer 토큰 또는 API Key"
                      className="w-full bg-white/5 border border-white/10 rounded-2xl pl-12 pr-5 py-3.5 text-sm focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all"
                    />
                  </div>
                </div>

                {/* 스캔 시작 버튼 */}
                <div className="col-span-12 md:col-span-2 flex flex-col justify-end">
                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-3.5 rounded-2xl bg-gradient-to-r from-primary-container via-primary to-[#2DD4D4] text-on-primary font-extrabold text-sm tracking-[0.08em] uppercase shadow-[0_8px_24px_rgba(14,165,165,0.35)] hover:shadow-[0_12px_32px_rgba(14,165,165,0.5)] hover:-translate-y-0.5 transition-all active:scale-[0.98] neon-glow-primary disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? (
                      <span className="flex items-center justify-center gap-2">
                        <span className="w-4 h-4 border-2 border-on-primary border-t-transparent rounded-full animate-spin" />
                        시작 중...
                      </span>
                    ) : (
                      <span className="flex items-center justify-center gap-2">
                        <span className="material-symbols-outlined text-lg" style={{ fontVariationSettings: "'FILL' 1" }}>
                          rocket_launch
                        </span>
                        스캔 시작
                      </span>
                    )}
                  </button>
                </div>
              </div>

              {/* 공격 벡터 + 에러 행 */}
              <div className="flex flex-wrap items-center gap-4 pt-1 border-t border-white/5">
                <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/50 shrink-0">
                  공격 벡터
                </span>
                {ATTACK_VECTORS.map((v) => {
                  const active = selectedVectors.includes(v.id);
                  const onlyOne = active && selectedVectors.length === 1;
                  return (
                    <button
                      key={v.id}
                      type="button"
                      title={onlyOne ? "최소 1개 벡터가 필요합니다" : undefined}
                      onClick={() => toggleVector(v.id)}
                      className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all border ${
                        active
                          ? "bg-primary/10 border-primary/30 text-primary hover:bg-primary/20"
                          : "bg-white/3 border-white/10 text-on-surface-variant hover:border-primary/30 hover:text-on-surface"
                      }`}
                    >
                      <span
                        className="material-symbols-outlined text-base"
                        style={active && v.fill ? { fontVariationSettings: "'FILL' 1" } : {}}
                      >
                        {v.icon}
                      </span>
                      {v.label}
                      {active && (
                        <span className="w-1.5 h-1.5 rounded-full bg-primary ml-0.5" />
                      )}
                    </button>
                  );
                })}

                {error && (
                  <div className="ml-auto flex items-center gap-2 px-4 py-2 rounded-xl bg-error/10 border border-error/20">
                    <span className="material-symbols-outlined text-error text-base">error</span>
                    <p className="text-xs text-error">{error}</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </form>

        {/* ─── 시스템 스탯 ─── */}
        <div className="grid grid-cols-3 gap-5">
          {[
            { icon: "bug_report", label: "지원 공격 패턴", value: "6,000+", color: "text-error", bg: "bg-error/5 border-error/10" },
            { icon: "layers", label: "분석 단계", value: "4 Phases", color: "text-primary", bg: "bg-primary/5 border-primary/10" },
            { icon: "verified_user", label: "판정 레이어", value: "3 Layers", color: "text-tertiary", bg: "bg-tertiary/5 border-tertiary/10" },
          ].map((card) => (
            <div
              key={card.label}
              className={`rounded-2xl p-5 flex items-center gap-5 border ${card.bg} transition-all hover:scale-[1.01]`}
            >
              <div className="w-11 h-11 rounded-xl bg-white/5 flex items-center justify-center shrink-0">
                <span className={`material-symbols-outlined text-2xl ${card.color}`} style={{ fontVariationSettings: "'FILL' 1" }}>
                  {card.icon}
                </span>
              </div>
              <div>
                <p className={`text-2xl font-black font-headline ${card.color}`}>{card.value}</p>
                <p className="text-[11px] text-on-surface-variant uppercase tracking-wider font-bold mt-0.5">{card.label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* ─── 최근 스캔 이력 ─── */}
        <section className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest mb-1">
                <span className="material-symbols-outlined text-xs">history</span>
                SCAN HISTORY
              </div>
              <h3 className="text-xl font-extrabold tracking-tight font-headline text-on-surface">
                최근 스캔 이력
              </h3>
            </div>
            {recentScans.length > 0 && (
              <span className="text-[10px] font-bold uppercase tracking-widest text-primary bg-primary/10 border border-primary/20 px-3 py-1.5 rounded-lg">
                {recentScans.length} Sessions
              </span>
            )}
          </div>

          {recentScans.length === 0 ? (
            <div className="glass-panel rounded-[2rem] p-16 flex flex-col items-center justify-center gap-6 text-center">
              <div className="w-20 h-20 rounded-[2rem] bg-primary/5 border border-primary/10 flex items-center justify-center">
                <span className="material-symbols-outlined text-4xl text-primary/30">radar</span>
              </div>
              <div>
                <p className="text-lg font-bold text-on-surface font-headline">스캔 이력 없음</p>
                <p className="text-sm text-on-surface-variant mt-1">
                  위 폼에서 스캔을 시작하면 결과가 여기에 표시됩니다.
                </p>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
              {recentScans.map((scan, idx) => {
                const meta = statusMeta(scan.status);
                const date = new Date(scan.created_at);
                return (
                  <div
                    key={scan.session_id}
                    onClick={() => router.push(`/scan/${scan.session_id}`)}
                    className="glass-panel rounded-[1.75rem] p-6 cursor-pointer hover:border-primary/20 hover:-translate-y-0.5 hover:shadow-[0_12px_30px_rgba(14,165,165,0.12)] transition-all group space-y-5"
                  >
                    {/* 카드 헤더 */}
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center shrink-0">
                          <span className="material-symbols-outlined text-primary text-lg">shield_search</span>
                        </div>
                        <div className="min-w-0">
                          <p className="font-bold text-on-surface group-hover:text-primary transition-colors truncate">
                            {scan.project_name}
                          </p>
                          <p className="text-[11px] font-mono text-on-surface-variant/60 truncate">
                            {scan.target_api_url}
                          </p>
                        </div>
                      </div>
                      <span className={`shrink-0 flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider border ${meta.cls}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
                        {meta.label}
                      </span>
                    </div>

                    {/* 카드 하단 메타 */}
                    <div className="flex items-center justify-between pt-4 border-t border-white/5">
                      <div className="flex items-center gap-2 text-[11px] text-on-surface-variant/60 font-mono">
                        <span className="material-symbols-outlined text-sm text-outline">schedule</span>
                        {date.toLocaleString("ko-KR", {
                          month: "2-digit",
                          day: "2-digit",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </div>
                      <div className="flex items-center gap-1.5 text-[11px] text-on-surface-variant/50 font-mono">
                        <span className="text-[10px] font-bold uppercase text-outline tracking-wider">ID</span>
                        {scan.session_id.slice(0, 12)}…
                      </div>
                      <span className="material-symbols-outlined text-on-surface-variant/30 group-hover:text-primary transition-colors text-lg">
                        arrow_forward
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* 팁 */}
        <div className="bg-primary/5 p-5 rounded-2xl border-l-4 border-primary/60 flex items-start gap-4">
          <span
            className="material-symbols-outlined text-primary neon-glow-primary shrink-0"
            style={{ fontVariationSettings: "'FILL' 1" }}
          >
            lightbulb
          </span>
          <p className="text-[11px] text-on-surface-variant leading-relaxed font-medium">
            <span className="font-bold text-on-surface uppercase tracking-wider">관제 최적화 팁 · </span>
            운영 엔드포인트의 경우 속도 제한을 피하기 위해 &apos;잠입&apos; 모드를 권장합니다.
            스캔 중 대상 서비스에 실제 요청이 전송됩니다.
          </p>
        </div>

      </div>
    </DashboardLayout>
  );
}
