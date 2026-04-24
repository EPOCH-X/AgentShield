"use client";

import DashboardLayout from "../../components/DashboardLayout";
import Link from "next/link";

const OWASP = [
  {
    id: "LLM01",
    name: "Prompt Injection",
    desc: "공격자가 LLM의 지시를 조작하여 의도치 않은 동작 유발",
    reason: "가장 흔한 공격. DB 스캔 + LLM 변형 모두 적용",
    color: "text-error",
    bg: "bg-error/10",
    border: "border-error/20",
    phases: [true, true, true, true],
  },
  {
    id: "LLM02",
    name: "Sensitive Info Disclosure",
    desc: "LLM이 민감정보(PII, API키, 내부데이터)를 응답에 포함",
    reason: "기업 데이터 유출 = 최대 비즈니스 리스크. 출력 필터 필수",
    color: "text-primary",
    bg: "bg-primary/10",
    border: "border-primary/20",
    phases: [true, true, true, true],
  },
  {
    id: "LLM06",
    name: "Excessive Agency",
    desc: "에이전트가 허가 없이 외부 API/DB에 접근",
    reason: "기업 AI 도입에서 핵심 문제. 도구 호출 검증 필요",
    color: "text-secondary",
    bg: "bg-secondary/10",
    border: "border-secondary/20",
    phases: [false, true, true, true],
  },
  {
    id: "LLM07",
    name: "System Prompt Leakage",
    desc: "시스템 프롬프트 내용이 사용자에게 노출",
    reason: "모든 공격의 진입점. 방어 우선순위 최상위",
    color: "text-tertiary",
    bg: "bg-tertiary/10",
    border: "border-tertiary/20",
    phases: [true, true, true, true],
  },
];

const PIPELINE = [
  {
    phase: "Phase 1",
    label: "DB 스캔",
    detail: "공격 DB 기반 자동 스캔 (규칙 기반 판정)",
    icon: "database",
    color: "text-error",
    bg: "bg-error/10",
    border: "border-error/20",
  },
  {
    phase: "Phase 2",
    label: "Red Agent",
    detail: "AI가 실패한 공격을 변형·재공격 (LLM + RAG)",
    icon: "psychology",
    color: "text-primary",
    bg: "bg-primary/10",
    border: "border-primary/20",
  },
  {
    phase: "Phase 3",
    label: "Blue Agent",
    detail: "방어 코드 자동 생성 (입력/출력 필터, 시스템프롬프트 패치)",
    icon: "shield",
    color: "text-secondary",
    bg: "bg-secondary/10",
    border: "border-secondary/20",
  },
  {
    phase: "Phase 4",
    label: "Defense Proxy",
    detail: "방어 코드 실제 적용 후 재검증 (Verify)",
    icon: "verified_user",
    color: "text-tertiary",
    bg: "bg-tertiary/10",
    border: "border-tertiary/20",
  },
];

const COMPETITORS = [
  { name: "Lakera Guard/Red", find: "별도 구매", fix: "없음", verify: "없음" },
  { name: "LLM Guard", find: "없음", fix: "없음", verify: "없음" },
  { name: "NeMo Guardrails", find: "없음", fix: "없음", verify: "없음" },
  { name: "AgentShield", find: "Phase 1-2 자동", fix: "Phase 3 자동", verify: "Phase 4 자동", isUs: true },
];

const STACK = [
  { layer: "AI 모델", tech: "Gemma 4 E2B (실질 2.3B)", role: "Red / Judge / Blue 3역할 QLoRA 어댑터" },
  { layer: "LLM 실행", tech: "Ollama", role: "로컬 LLM 실행" },
  { layer: "워크플로우", tech: "LangGraph", role: "Phase 1→2→3→4 상태 그래프" },
  { layer: "벡터 DB", tech: "ChromaDB", role: "방어 패턴 / 공격 기록 의미 검색 (RAG)" },
  { layer: "관계형 DB", tech: "PostgreSQL", role: "공격 DB, 테스트 결과, 사용 로그, 위반 이력" },
  { layer: "백엔드", tech: "FastAPI", role: "REST API, WebSocket" },
  { layer: "프론트엔드", tech: "Next.js 14", role: "대시보드, 보고서, 모니터링 화면" },
  { layer: "인증", tech: "JWT", role: "관리자 / 감사자 / 직원 역할 분리" },
];

export default function OverviewPage() {
  return (
    <DashboardLayout>
      <div className="p-10 max-w-[1400px] mx-auto w-full space-y-14">

        {/* ── 히어로 ── */}
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest">
            <span className="material-symbols-outlined text-xs">info</span>
            PLATFORM OVERVIEW
          </div>
          <h1 className="text-5xl font-extrabold tracking-tight font-headline text-white leading-tight">
            AgentShield
          </h1>
          <p className="text-xl text-on-surface-variant max-w-3xl leading-relaxed">
            AI 챗봇/에이전트의 보안 취약점을{" "}
            <span className="text-error font-bold">Find</span>하고,
            방어 코드를{" "}
            <span className="text-primary font-bold">Fix</span>하고,
            실제로 방어되는지{" "}
            <span className="text-secondary font-bold">Verify</span>하는 플랫폼.
          </p>
          <p className="text-sm text-on-surface-variant/70 max-w-2xl">
            기존 도구(Lakera, LLM Guard, NeMo Guardrails)는 "방어만" 하거나 "발견만" 한다.
            AgentShield는 <span className="text-white font-bold">Find → Fix → Verify</span>를 하나의 파이프라인으로 자동화한다.
          </p>
          <div className="flex gap-4 pt-2">
            <Link href="/scan" className="inline-flex items-center gap-2 px-6 py-3 rounded-2xl bg-primary text-on-primary font-bold text-sm hover:-translate-y-0.5 transition-all shadow-lg shadow-primary/30">
              <span className="material-symbols-outlined text-sm">shield_search</span>
              스캔 시작
            </Link>
            <Link href="/monitoring" className="inline-flex items-center gap-2 px-6 py-3 rounded-2xl bg-white/5 border border-white/10 text-on-surface font-bold text-sm hover:bg-white/10 transition-all">
              <span className="material-symbols-outlined text-sm">monitoring</span>
              모니터링
            </Link>
          </div>
        </div>

        {/* ── 4단계 파이프라인 ── */}
        <div className="space-y-6">
          <div>
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest mb-2">
              <span className="material-symbols-outlined text-xs">layers</span>
              SCAN PIPELINE — 기능 A: AI Agent Shield
            </div>
            <h2 className="text-2xl font-extrabold font-headline text-white">4단계 자동화 파이프라인</h2>
            <p className="text-sm text-on-surface-variant mt-1">타겟 AI 챗봇 API URL 입력 → 자동 취약점 발견 → 방어 코드 생성 → 재검증 → PDF 보고서</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {PIPELINE.map((p, i) => (
              <div key={p.phase} className="relative">
                <div className={`glass-panel rounded-2xl p-6 space-y-4 border ${p.border} h-full`}>
                  <div className="flex items-center justify-between">
                    <span className={`text-[10px] font-black uppercase tracking-widest ${p.color}`}>{p.phase}</span>
                    <div className={`w-10 h-10 rounded-xl ${p.bg} flex items-center justify-center`}>
                      <span className={`material-symbols-outlined text-lg ${p.color}`}
                        style={{ fontVariationSettings: "'FILL' 1" }}>{p.icon}</span>
                    </div>
                  </div>
                  <div>
                    <p className={`text-lg font-black font-headline ${p.color}`}>{p.label}</p>
                    <p className="text-xs text-on-surface-variant mt-1 leading-relaxed">{p.detail}</p>
                  </div>
                </div>
                {i < PIPELINE.length - 1 && (
                  <div className="hidden md:flex absolute -right-2 top-1/2 -translate-y-1/2 z-10 w-4 h-4 items-center justify-center">
                    <span className="material-symbols-outlined text-on-surface-variant/30 text-sm">arrow_forward</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* ── 기능 B: 직원 모니터링 ── */}
        <div className="glass-panel rounded-2xl p-8 space-y-5">
          <div>
            <div className="flex items-center gap-2 text-secondary font-bold text-xs uppercase tracking-widest mb-2">
              <span className="material-symbols-outlined text-xs">monitoring</span>
              기능 B: 직원 AI 사용 모니터링
            </div>
            <h2 className="text-2xl font-extrabold font-headline text-white">직원 AI 모니터링</h2>
            <p className="text-sm text-on-surface-variant mt-1">기능 A의 Defense Proxy 아키텍처를 재활용하여 직원 AI 트래픽을 실시간 감시</p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { id: "P1", label: "기밀 유출 방지", desc: "PII, 소스코드, API키 입력 차단", icon: "data_loss_prevention", color: "text-error", bg: "bg-error/10" },
              { id: "P2", label: "부적절 사용 탐지", desc: "업무 무관, 유해 콘텐츠 필터링", icon: "terminal", color: "text-primary", bg: "bg-primary/10" },
              { id: "P3", label: "과도한 사용 제한", desc: "Rate Limit 초과 감지 및 제재", icon: "speed", color: "text-secondary", bg: "bg-secondary/10" },
              { id: "P4", label: "사용 통계 대시보드", desc: "위반 이력 + 부서별 현황", icon: "bar_chart", color: "text-tertiary", bg: "bg-tertiary/10" },
            ].map((item) => (
              <div key={item.id} className="bg-white/3 border border-white/8 rounded-2xl p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-black uppercase tracking-widest ${item.color}`}>{item.id}</span>
                  <div className={`ml-auto w-8 h-8 rounded-xl ${item.bg} flex items-center justify-center`}>
                    <span className={`material-symbols-outlined text-sm ${item.color}`}>{item.icon}</span>
                  </div>
                </div>
                <p className={`font-bold text-sm ${item.color}`}>{item.label}</p>
                <p className="text-xs text-on-surface-variant leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
          <div className="flex gap-3 pt-2">
            <Link href="/monitoring" className="inline-flex items-center gap-2 text-sm font-bold text-secondary hover:text-secondary/80 transition-colors">
              모니터링 대시보드 →
            </Link>
            <span className="text-on-surface-variant/30">|</span>
            <Link href="/monitoring/admin" className="inline-flex items-center gap-2 text-sm font-bold text-secondary hover:text-secondary/80 transition-colors">
              관리자 콘솔 →
            </Link>
          </div>
        </div>

        {/* ── OWASP 커버리지 ── */}
        <div className="space-y-6">
          <div>
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest mb-2">
              <span className="material-symbols-outlined text-xs">security</span>
              OWASP LLM TOP 10
            </div>
            <h2 className="text-2xl font-extrabold font-headline text-white">4개 카테고리 완전 커버</h2>
            <p className="text-sm text-on-surface-variant mt-1">10개를 피상적으로 다루는 것보다 4개를 완전히 커버하는 것이 실무적으로 더 가치 있다.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {OWASP.map((item) => (
              <div key={item.id} className={`glass-panel rounded-2xl p-6 space-y-4 border ${item.border}`}>
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <span className={`text-[10px] font-black uppercase tracking-widest ${item.color}`}>{item.id}</span>
                    <p className={`text-lg font-bold font-headline mt-0.5 ${item.color}`}>{item.name}</p>
                  </div>
                  <span className={`text-[10px] font-black px-2 py-1 rounded ${item.bg} ${item.color} whitespace-nowrap`}>완전 커버</span>
                </div>
                <p className="text-sm text-on-surface-variant">{item.desc}</p>
                <p className="text-xs text-on-surface-variant/60 italic">{item.reason}</p>
                <div className="flex gap-2">
                  {item.phases.map((covered, i) => (
                    <div key={i} className={`flex-1 h-1.5 rounded-full ${covered ? item.bg.replace('/10', '/40') : 'bg-white/5'}`} />
                  ))}
                </div>
                <p className="text-[10px] text-on-surface-variant/40 uppercase tracking-widest">Phase 1 · 2 · 3 · 4</p>
              </div>
            ))}
          </div>
        </div>

        {/* ── 경쟁사 비교 ── */}
        <div className="space-y-6">
          <div>
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest mb-2">
              <span className="material-symbols-outlined text-xs">compare</span>
              COMPETITIVE ANALYSIS
            </div>
            <h2 className="text-2xl font-extrabold font-headline text-white">Find + Fix + Verify 자동화</h2>
            <p className="text-sm text-on-surface-variant mt-1">이 세 가지를 하나로 자동화하는 오픈소스는 없다. 이것이 AgentShield의 차별점.</p>
          </div>
          <div className="glass-panel rounded-2xl overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/10 bg-white/3">
                  <th className="px-6 py-4 text-[10px] font-black text-outline tracking-widest uppercase">솔루션</th>
                  <th className="px-6 py-4 text-[10px] font-black text-error tracking-widest uppercase text-center">Find (취약점 발견)</th>
                  <th className="px-6 py-4 text-[10px] font-black text-primary tracking-widest uppercase text-center">Fix (방어 생성)</th>
                  <th className="px-6 py-4 text-[10px] font-black text-secondary tracking-widest uppercase text-center">Verify (재검증)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {COMPETITORS.map((c) => (
                  <tr key={c.name} className={c.isUs ? "bg-primary/5" : ""}>
                    <td className={`px-6 py-4 font-bold text-sm ${c.isUs ? "text-primary" : "text-on-surface-variant"}`}>
                      {c.isUs && <span className="material-symbols-outlined text-sm mr-2 align-middle">shield</span>}
                      {c.name}
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className={`text-xs font-bold ${c.isUs ? "text-error" : "text-on-surface-variant/40"}`}>{c.find}</span>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className={`text-xs font-bold ${c.isUs ? "text-primary" : "text-on-surface-variant/40"}`}>{c.fix}</span>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className={`text-xs font-bold ${c.isUs ? "text-secondary" : "text-on-surface-variant/40"}`}>{c.verify}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── 기술 스택 ── */}
        <div className="space-y-6">
          <div>
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest mb-2">
              <span className="material-symbols-outlined text-xs">developer_mode</span>
              TECH STACK
            </div>
            <h2 className="text-2xl font-extrabold font-headline text-white">기술 스택</h2>
            <p className="text-sm text-on-surface-variant mt-1">
              <span className="text-white font-bold">Gemma 4 E2B</span> (실질 2.3B, 총 ~5.1B) · QLoRA ~8GB VRAM · Apache 2.0
            </p>
          </div>
          <div className="glass-panel rounded-2xl overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/10 bg-white/3">
                  <th className="px-6 py-4 text-[10px] font-black text-outline tracking-widest uppercase">영역</th>
                  <th className="px-6 py-4 text-[10px] font-black text-outline tracking-widest uppercase">기술</th>
                  <th className="px-6 py-4 text-[10px] font-black text-outline tracking-widest uppercase">용도</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {STACK.map((s) => (
                  <tr key={s.layer} className="hover:bg-white/3 transition-colors">
                    <td className="px-6 py-3 text-xs font-black text-outline uppercase tracking-widest">{s.layer}</td>
                    <td className="px-6 py-3 text-sm font-bold text-primary">{s.tech}</td>
                    <td className="px-6 py-3 text-sm text-on-surface-variant">{s.role}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── 팀 ── */}
        <div className="glass-panel rounded-2xl p-8 space-y-5">
          <div>
            <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest mb-2">
              <span className="material-symbols-outlined text-xs">group</span>
              TEAM
            </div>
            <h2 className="text-2xl font-extrabold font-headline text-white">팀 구성 (7명)</h2>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { role: "R1 (리드)", area: "Phase 2 Red Agent + Judge 판정 + LangGraph + 전체 관리" },
              { role: "R2", area: "Phase 1 DB 스캐너 + 데이터 적재" },
              { role: "R3", area: "Phase 3 Blue Agent + Phase 4 Defense Proxy" },
              { role: "R4", area: "RAG 구축 + Ollama 연동 + 학습 코드" },
              { role: "R5", area: "기능 B: 모니터링 Proxy + 정책 엔진" },
              { role: "R6", area: "프론트엔드 전체 (기능 A + B 화면)" },
              { role: "R7", area: "백엔드 API + DB + 보고서 + 테스트" },
            ].map((m) => (
              <div key={m.role} className="bg-white/3 border border-white/8 rounded-xl p-4 space-y-1">
                <p className="text-xs font-black text-primary uppercase tracking-widest">{m.role}</p>
                <p className="text-xs text-on-surface-variant leading-relaxed">{m.area}</p>
              </div>
            ))}
          </div>
        </div>

      </div>
    </DashboardLayout>
  );
}
