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
    // 최근 스캔 로컬 저장에서 복원
    try {
      const stored = localStorage.getItem("recent_scans");
      if (stored) setRecentScans(JSON.parse(stored));
    } catch {
      // 무시
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

  function statusBadge(status: string) {
    const map: Record<string, { cls: string; label: string }> = {
      completed: { cls: "bg-tertiary/10 text-tertiary border-tertiary/20", label: "완료" },
      running: { cls: "bg-primary/10 text-primary border-primary/20", label: "실행 중" },
      failed: { cls: "bg-error/10 text-error border-error/20", label: "실패" },
      pending: { cls: "bg-outline/10 text-outline border-outline/20", label: "대기" },
    };
    const s = map[status] || map.pending;
    return (
      <span className={`px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider border ${s.cls}`}>
        {s.label}
      </span>
    );
  }

  return (
    <DashboardLayout>
      <div className="p-10 grid grid-cols-12 gap-10 max-w-[1700px] mx-auto w-full">
        {/* 왼쪽: 스캔 설정 */}
        <section className="col-span-12 lg:col-span-4 space-y-8">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest mb-1">
              <span className="material-symbols-outlined text-xs">shield</span>
              ADVERSARIAL TESTING
            </div>
            <h2 className="text-4xl font-extrabold tracking-tight font-headline text-on-surface">
              LLM 취약점 스캔
            </h2>
            <p className="text-on-surface-variant/80 text-sm">
              심층적인 적대적 테스트를 위한 모델 엔드포인트를 구성하십시오.
            </p>
            <p className="text-[11px] text-outline">
              <Link
                href="/overview"
                className="text-primary/90 hover:text-primary font-bold underline-offset-2 hover:underline"
              >
                플랫폼 개요
              </Link>
              에서 기능 A·B와 공유 컴포넌트 관계를 확인할 수 있습니다.
            </p>
          </div>

          <form onSubmit={handleStartScan}>
            <div className="glass-panel rounded-[2rem] p-8 shadow-2xl relative overflow-hidden space-y-8">
              <div className="absolute -top-24 -right-24 w-48 h-48 bg-primary/5 rounded-full blur-3xl" />

              <div className="space-y-6 relative z-10">
                {/* 프로젝트 이름 */}
                <div className="space-y-3">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60 flex justify-between items-center">
                    프로젝트 식별 정보
                    <span className="material-symbols-outlined text-primary/60 text-xs cursor-help">
                      help_outline
                    </span>
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      value={projectName}
                      onChange={(e) => setProjectName(e.target.value)}
                      placeholder="프로젝트 이름"
                      className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-sm focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all"
                    />
                    <span className="absolute right-4 top-1/2 -translate-y-1/2 material-symbols-outlined text-on-surface-variant/30 text-lg">
                      edit
                    </span>
                  </div>
                </div>

                {/* 대상 URL */}
                <div className="space-y-3">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    대상 URL / API 엔드포인트
                  </label>
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-primary/60 text-lg">
                      api
                    </span>
                    <input
                      type="text"
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="https://..."
                      className="w-full bg-white/5 border border-white/10 rounded-2xl pl-12 pr-6 py-4 text-sm font-mono focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all"
                    />
                  </div>
                </div>

                <div className="space-y-3">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    대상 API 키
                  </label>
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-primary/60 text-lg">
                      key
                    </span>
                    <input
                      type="password"
                      value={targetApiKey}
                      onChange={(e) => setTargetApiKey(e.target.value)}
                      placeholder="선택 입력: Bearer 토큰 또는 API Key"
                      className="w-full bg-white/5 border border-white/10 rounded-2xl pl-12 pr-6 py-4 text-sm focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all"
                    />
                  </div>
                  <p className="text-[10px] text-on-surface-variant/70 leading-relaxed">
                    공통 target adapter가 URL 패턴을 보고 요청 형식을 자동 감지합니다. 기본 입력은 URL과 키만 있으면 됩니다.
                  </p>
                </div>

                {/* 공격 벡터 프리셋 */}
                <div className="space-y-4">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    공격 벡터 프리셋
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    {ATTACK_VECTORS.map((v) => {
                      const active = selectedVectors.includes(v.id);
                      const onlyOne = active && selectedVectors.length === 1;
                      return (
                        <button
                          key={v.id}
                          type="button"
                          title={onlyOne ? "최소 1개 벡터가 필요합니다" : undefined}
                          onClick={() => toggleVector(v.id)}
                          className={`p-4 rounded-2xl flex flex-col items-start gap-3 transition-all ${
                            active
                              ? "bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20"
                              : "bg-white/3 border border-white/10 text-on-surface-variant hover:text-on-surface hover:border-primary/30"
                          } ${onlyOne ? "ring-1 ring-primary/20" : ""}`}
                        >
                          <span
                            className="material-symbols-outlined text-2xl"
                            style={
                              active && v.fill
                                ? { fontVariationSettings: "'FILL' 1" }
                                : {}
                            }
                          >
                            {v.icon}
                          </span>
                          <span className="text-xs font-bold">{v.label}</span>
                        </button>
                      );
                    })}
                  </div>
                  <p className="text-[10px] text-on-surface-variant/70 leading-relaxed">
                    벡터 선택은 현재 UI 프리셋이다. 실제 스캔은 공통 DB 공격 패턴과 graph 파이프라인으로 실행된다.
                  </p>
                </div>
              </div>

              {/* 에러 */}
              {error && (
                <div className="flex items-center gap-3 p-4 rounded-2xl bg-error/10 border border-error/20">
                  <span className="material-symbols-outlined text-error">error</span>
                  <p className="text-sm text-error">{error}</p>
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full py-5 rounded-[1.25rem] bg-gradient-to-r from-primary-container via-primary to-[#2DD4D4] text-on-primary font-extrabold text-sm tracking-[0.1em] uppercase shadow-[0_10px_30px_rgba(14,165,165,0.35)] hover:shadow-[0_15px_40px_rgba(14,165,165,0.5)] hover:-translate-y-0.5 transition-all active:scale-[0.98] neon-glow-primary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="w-4 h-4 border-2 border-on-primary border-t-transparent rounded-full animate-spin" />
                    스캔 시작 중...
                  </span>
                ) : (
                  "시스템 스캔 시작"
                )}
              </button>
            </div>
          </form>

          {/* 팁 */}
          <div className="bg-primary/5 p-6 rounded-2xl border-l-4 border-primary/60 flex items-start gap-4">
            <span
              className="material-symbols-outlined text-primary neon-glow-primary"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              lightbulb
            </span>
            <div className="space-y-1">
              <p className="text-xs font-bold text-on-surface uppercase tracking-wider">
                관제 최적화 팁
              </p>
              <p className="text-[11px] text-on-surface-variant leading-relaxed font-medium">
                운영 엔드포인트의 경우 속도 제한을 피하기 위해 &apos;잠입&apos; 모드를 권장합니다.
                스캔 중 대상 서비스에 실제 요청이 전송됩니다.
              </p>
            </div>
          </div>
        </section>

        {/* 오른쪽: 최근 스캔 히스토리 */}
        <section className="col-span-12 lg:col-span-8 space-y-8">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest mb-2">
                <span className="material-symbols-outlined text-xs">history</span>
                SCAN HISTORY
              </div>
              <h2 className="text-2xl font-extrabold tracking-tight font-headline text-on-surface">
                최근 스캔 이력
              </h2>
            </div>
          </div>

          {recentScans.length === 0 ? (
            <div className="glass-panel rounded-[2rem] p-16 flex flex-col items-center justify-center gap-6 text-center">
              <div className="w-20 h-20 rounded-[2rem] bg-primary/5 border border-primary/10 flex items-center justify-center">
                <span className="material-symbols-outlined text-4xl text-primary/30">
                  radar
                </span>
              </div>
              <div>
                <p className="text-lg font-bold text-on-surface font-headline">
                  스캔 이력 없음
                </p>
                <p className="text-sm text-on-surface-variant mt-1">
                  왼쪽 패널에서 스캔을 시작하면 결과가 여기에 표시됩니다.
                </p>
              </div>
            </div>
          ) : (
            <div className="glass-panel rounded-[2rem] overflow-hidden shadow-2xl">
              <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between">
                <h3 className="font-headline font-bold text-lg flex items-center gap-3 text-white">
                  <span className="material-symbols-outlined text-primary">security</span>
                  스캔 세션 목록
                </h3>
                <span className="text-[10px] font-bold uppercase tracking-widest text-primary bg-primary/10 border border-primary/20 px-3 py-1.5 rounded-lg">
                  {recentScans.length} Sessions
                </span>
              </div>
              <div className="divide-y divide-white/5">
                {recentScans.map((scan) => (
                  <div
                    key={scan.session_id}
                    onClick={() => router.push(`/scan/${scan.session_id}`)}
                    className="px-8 py-5 flex items-center justify-between hover:bg-white/3 transition-all cursor-pointer group"
                  >
                    <div className="flex items-center gap-5">
                      <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
                        <span className="material-symbols-outlined text-primary text-lg">
                          shield_search
                        </span>
                      </div>
                      <div>
                        <p className="font-bold text-on-surface group-hover:text-primary transition-colors">
                          {scan.project_name}
                        </p>
                        <p className="text-xs font-mono text-on-surface-variant mt-0.5 truncate max-w-xs">
                          {scan.target_api_url}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {statusBadge(scan.status)}
                      <p className="text-[11px] font-mono text-on-surface-variant/60">
                        {new Date(scan.created_at).toLocaleString("ko-KR", {
                          month: "2-digit",
                          day: "2-digit",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </p>
                      <span className="material-symbols-outlined text-on-surface-variant/30 group-hover:text-primary transition-colors text-lg">
                        chevron_right
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 시스템 정보 카드 */}
          <div className="grid grid-cols-3 gap-6">
            {[
              { icon: "bug_report", label: "지원 공격 패턴", value: "6,000+", color: "text-error" },
              { icon: "layers", label: "분석 단계", value: "4 Phases", color: "text-primary" },
              { icon: "verified_user", label: "판정 레이어", value: "3 Layers", color: "text-tertiary" },
            ].map((card) => (
              <div
                key={card.label}
                className="glass-panel rounded-[1.5rem] p-6 flex flex-col gap-4 hover:border-primary/20 transition-all"
              >
                <span className={`material-symbols-outlined text-2xl ${card.color}`}>
                  {card.icon}
                </span>
                <div>
                  <p className={`text-2xl font-black font-headline ${card.color}`}>{card.value}</p>
                  <p className="text-[11px] text-on-surface-variant mt-1 uppercase tracking-wider font-bold">
                    {card.label}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </DashboardLayout>
  );
}
