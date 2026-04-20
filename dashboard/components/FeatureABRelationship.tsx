"use client";

const ROWS: { shared: string; featureA: string; featureB: string }[] = [
  {
    shared: "Proxy 서버 코드",
    featureA: "Defense Proxy (Phase 4 재검증)",
    featureB: "Monitoring Proxy (직원 트래픽 감시)",
  },
  {
    shared: "PII 정규식",
    featureA: "LLM02 판정 + 출력 필터",
    featureB: "P1 기밀 유출 탐지",
  },
  {
    shared: "PostgreSQL",
    featureA: "공격 패턴, 테스트 결과 저장",
    featureB: "사용 로그, 위반 이력 저장",
  },
  {
    shared: "FastAPI 백엔드",
    featureA: "Phase 1–4 실행 API",
    featureB: "모니터링 / 관리자 API",
  },
  {
    shared: "Next.js 대시보드",
    featureA: "취약점 맵, 보고서 뷰어",
    featureB: "사용 현황, 위반 알림",
  },
];

export default function FeatureABRelationship() {
  return (
    <section className="space-y-4">
      <div className="flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest">
        <span className="material-symbols-outlined text-sm">hub</span>
        Shared infrastructure
      </div>
      <h3 className="text-xl font-extrabold font-headline text-on-surface tracking-tight">
        기능 A와 기능 B의 관계
      </h3>
      <p className="text-sm text-on-surface-variant/90 leading-relaxed max-w-3xl">
        두 기능은 목적이 다르지만, 프록시·정규식·DB·API·이 대시보드를 함께 써서 구현을 맞춥니다. 아래는{" "}
        <span className="text-on-surface font-semibold">공유 컴포넌트</span>가 각 기능에서 어떻게
        쓰이는지 요약입니다.
      </p>

      <div className="overflow-x-auto rounded-2xl border border-white/10 bg-surface-container-low/40">
        <table className="w-full min-w-[640px] text-left text-sm border-collapse">
          <thead>
            <tr className="bg-surface-container-highest/40 border-b border-white/10">
              <th className="px-4 py-3.5 text-[10px] font-black uppercase tracking-widest text-outline w-[22%]">
                공유 컴포넌트
              </th>
              <th className="px-4 py-3.5 text-[10px] font-black uppercase tracking-widest text-primary w-[39%]">
                기능 A 사용처
              </th>
              <th className="px-4 py-3.5 text-[10px] font-black uppercase tracking-widest text-tertiary w-[39%]">
                기능 B 사용처
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {ROWS.map((row) => (
              <tr key={row.shared} className="hover:bg-white/[0.03] transition-colors">
                <td className="px-4 py-3.5 font-bold text-on-surface align-top whitespace-nowrap">
                  {row.shared}
                </td>
                <td className="px-4 py-3.5 text-on-surface-variant align-top leading-snug">{row.featureA}</td>
                <td className="px-4 py-3.5 text-on-surface-variant align-top leading-snug">{row.featureB}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-[11px] text-outline leading-relaxed">
        백엔드는 동일 FastAPI 앱에서 경로만 나뉩니다. 예:{" "}
        <code className="font-mono text-primary/90">/api/v1/scan/*</code> ·{" "}
        <code className="font-mono text-tertiary/90">/api/v1/monitoring/*</code>
      </p>
    </section>
  );
}
