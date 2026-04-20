"use client";

import DashboardLayout from "../../components/DashboardLayout";
import FeatureABRelationship from "../../components/FeatureABRelationship";

const FEATURE_A_STEPS = [
  "Phase 1: DB 공격 프롬프트 자동 스캔 (규칙 기반)",
  "Phase 2: Red Agent 변형 재공격 (LLM + RAG)",
  "Phase 3: Blue Agent 방어 코드 생성 (LLM + RAG)",
  "Phase 4: Defense Proxy 적용 후 재검증",
  "보고서: 취약점 + 방어 코드 + 전후 비교 PDF",
];

const FEATURE_B_STEPS = [
  "P1: 기밀 유출 방지 (PII, 소스코드, API 키 등)",
  "P2: 부적절 사용 탐지 (업무 무관, 유해 콘텐츠)",
  "P3: Rate Limit",
  "P4: 애매한 요청 LLM 2차 의도 판정",
  "P5: 사용 통계 · 위반 이력 대시보드",
];

export default function OverviewPage() {
  return (
    <DashboardLayout>
      <div className="p-10 max-w-[1700px] mx-auto w-full space-y-10">
        <header className="space-y-2">
          <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-[0.2em]">
            <span className="w-8 h-px bg-primary" />
            AgentShield
          </div>
          <h1 className="text-4xl font-headline font-extrabold tracking-tight text-white">플랫폼 개요</h1>
          <p className="text-on-surface-variant max-w-2xl text-sm leading-relaxed">
            기능 A는 <strong className="text-on-surface">타겟 챗봇</strong>을 공격 관점에서 검증하고 방어·재검증까지 수행합니다.
            기능 B는 <strong className="text-on-surface">직원 AI 사용</strong>을 프록시로 감시하고 정책 위반을 기록합니다.
          </p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <article className="glass-panel rounded-[2rem] p-8 shadow-2xl border border-primary/15 space-y-5">
            <div className="flex items-center gap-3">
              <div className="w-11 h-11 rounded-xl bg-primary/15 border border-primary/25 flex items-center justify-center">
                <span className="material-symbols-outlined text-primary text-xl" style={{ fontVariationSettings: "'FILL' 1" }}>
                  shield_lock
                </span>
              </div>
              <div>
                <h2 className="text-lg font-black font-headline text-on-surface">기능 A: AI Agent Shield</h2>
                <p className="text-[10px] uppercase tracking-widest text-primary font-bold">핵심 · Find → Fix → Verify</p>
              </div>
            </div>
            <p className="text-xs text-on-surface-variant leading-relaxed">
              타겟 AI 챗봇 API URL을 입력하면 아래 파이프라인이 순차 실행됩니다.
            </p>
            <ol className="space-y-2.5 list-decimal list-inside text-sm text-on-surface-variant marker:text-primary marker:font-bold">
              {FEATURE_A_STEPS.map((s) => (
                <li key={s} className="pl-1">
                  <span className="text-on-surface/90">{s}</span>
                </li>
              ))}
            </ol>
            <p className="text-[11px] text-outline pt-2 border-t border-white/5">
              UI: <span className="font-mono text-on-surface-variant">/scan</span>,{" "}
              <span className="font-mono text-on-surface-variant">/report</span>
            </p>
          </article>

          <article className="glass-panel rounded-[2rem] p-8 shadow-2xl border border-white/10 space-y-5">
            <div className="flex items-center gap-3">
              <div className="w-11 h-11 rounded-xl bg-tertiary/10 border border-tertiary/20 flex items-center justify-center">
                <span className="material-symbols-outlined text-tertiary text-xl" style={{ fontVariationSettings: "'FILL' 1" }}>
                  visibility
                </span>
              </div>
              <div>
                <h2 className="text-lg font-black font-headline text-on-surface">기능 B: 직원 AI 모니터링</h2>
                <p className="text-[10px] uppercase tracking-widest text-tertiary font-bold">Sentinel · Policy · usage</p>
              </div>
            </div>
            <p className="text-xs text-on-surface-variant leading-relaxed">
              기업 내 직원의 AI 챗봇 사용을 Monitoring Proxy로 통과시키며 정책을 적용합니다.
            </p>
            <ul className="space-y-2.5 text-sm text-on-surface-variant">
              {FEATURE_B_STEPS.map((s) => (
                <li key={s} className="flex gap-2.5">
                  <span className="material-symbols-outlined text-tertiary text-base shrink-0">chevron_right</span>
                  <span className="text-on-surface/90">{s}</span>
                </li>
              ))}
            </ul>
            <p className="text-[11px] text-outline pt-2 border-t border-white/5">
              Defense Proxy와 유사한 <strong className="text-on-surface-variant">레이어드 프록시</strong> 패턴을 참고합니다.
            </p>
            <p className="text-[11px] text-outline">
              UI: <span className="font-mono text-on-surface-variant">/monitoring</span>,{" "}
              <span className="font-mono text-on-surface-variant">/monitoring/admin</span>
            </p>
          </article>
        </div>

        <div className="glass-panel rounded-[2rem] p-8 md:p-10 shadow-2xl">
          <FeatureABRelationship />
        </div>
      </div>
    </DashboardLayout>
  );
}
