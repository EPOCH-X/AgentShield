"use client";

import { useEffect, useState } from "react";

interface Props {
  phase: number;
  status: string;
  vulnerableCount: number;
  completedTests: number;
  latestAttackPrompt?: string;
}

type NodeId = 0 | 1 | 2 | 3 | 4;

const NODES = [
  {
    id: 0 as NodeId,
    emoji: "🗡",
    label: "공격 프롬프트",
    sub: "Red Agent",
    color: "#ef4444",
    glow: "rgba(239,68,68,0.55)",
    glowSoft: "rgba(239,68,68,0.15)",
    bgActive: "rgba(239,68,68,0.18)",
    bgDone: "rgba(239,68,68,0.07)",
  },
  {
    id: 1 as NodeId,
    emoji: "💬",
    label: "챗봇 응답",
    sub: "Target API",
    color: "#0ea5a5",
    glow: "rgba(14,165,165,0.55)",
    glowSoft: "rgba(14,165,165,0.15)",
    bgActive: "rgba(14,165,165,0.18)",
    bgDone: "rgba(14,165,165,0.07)",
  },
  {
    id: 2 as NodeId,
    emoji: "⚖",
    label: "Judge 판정",
    sub: "멀티에이전트",
    color: "#a78bfa",
    glow: "rgba(167,139,250,0.55)",
    glowSoft: "rgba(167,139,250,0.15)",
    bgActive: "rgba(167,139,250,0.18)",
    bgDone: "rgba(167,139,250,0.07)",
  },
  {
    id: 3 as NodeId,
    emoji: "🛡",
    label: "방어 생성",
    sub: "Blue Agent",
    color: "#60a5fa",
    glow: "rgba(96,165,250,0.55)",
    glowSoft: "rgba(96,165,250,0.15)",
    bgActive: "rgba(96,165,250,0.18)",
    bgDone: "rgba(96,165,250,0.07)",
  },
  {
    id: 4 as NodeId,
    emoji: "✅",
    label: "검증 완료",
    sub: "Verify Phase",
    color: "#34d399",
    glow: "rgba(52,211,153,0.55)",
    glowSoft: "rgba(52,211,153,0.15)",
    bgActive: "rgba(52,211,153,0.18)",
    bgDone: "rgba(52,211,153,0.07)",
  },
] as const;

function getActiveNode(phase: number, subStep: number, isDone: boolean): NodeId {
  if (isDone) return 4;
  if (phase <= 2) return ([0, 1, 2][subStep % 3]) as NodeId;
  if (phase === 3) return 3;
  return 4;
}

function isNodeDone(nodeId: number, phase: number, isDone: boolean): boolean {
  if (isDone) return true;
  if (phase >= 3 && nodeId <= 2) return true;
  if (phase >= 4 && nodeId === 3) return true;
  return false;
}

export default function PipelineFlowViz({
  phase,
  status,
  vulnerableCount,
  completedTests,
  latestAttackPrompt,
}: Props) {
  const isRunning = status === "running" || status === "pending";
  const isDone = status === "completed";

  const [subStep, setSubStep] = useState(0);
  const [flashNode, setFlashNode] = useState<NodeId | null>(null);
  // completed 상태에서도 순환 애니메이션 (전체 5노드 사이클)
  const [demoStep, setDemoStep] = useState(0);

  useEffect(() => {
    if (!isRunning) return;
    const interval = setInterval(() => {
      setSubStep((prev) => {
        const next = phase <= 2 ? (prev + 1) % 3 : prev;
        const nextActive = getActiveNode(phase, next, false);
        setFlashNode(nextActive);
        setTimeout(() => setFlashNode(null), 400);
        return next;
      });
    }, 1400);
    return () => clearInterval(interval);
  }, [isRunning, phase]);

  // completed 상태 순환: 0→1→2→3→4→0...
  useEffect(() => {
    if (!isDone) return;
    const interval = setInterval(() => {
      setDemoStep((prev) => {
        const next = (prev + 1) % 5;
        setFlashNode(next as NodeId);
        setTimeout(() => setFlashNode(null), 400);
        return next;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [isDone]);

  const activeNode: NodeId = isDone
    ? (demoStep as NodeId)
    : getActiveNode(phase, subStep, false);
  const loopActive = vulnerableCount > 0 && isRunning && phase <= 2;

  return (
    <>
      {/* custom keyframes */}
      <style dangerouslySetInnerHTML={{ __html: `
        @keyframes nodePulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.06); }
        }
        @keyframes nodeFlash {
          0% { opacity: 0; transform: scale(0.85); }
          40% { opacity: 1; transform: scale(1.1); }
          100% { opacity: 1; transform: scale(1); }
        }
        @keyframes ringPing {
          0% { transform: scale(1); opacity: 0.9; }
          100% { transform: scale(1.7); opacity: 0; }
        }
        @keyframes particleFlow {
          from { transform: translateX(-100%); opacity: 1; }
          to { transform: translateX(400%); opacity: 0.3; }
        }
        @keyframes glowBreath {
          0%, 100% { opacity: 0.6; }
          50% { opacity: 1; }
        }
        @keyframes labelPop {
          0% { transform: scale(0.9); opacity: 0.5; }
          60% { transform: scale(1.05); }
          100% { transform: scale(1); opacity: 1; }
        }
      `}} />

      <div className="glass-panel rounded-[2rem] p-7 shadow-xl overflow-hidden">
        {/* 헤더 */}
        <div className="flex items-center justify-between mb-7">
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-black uppercase tracking-[0.3em] text-on-surface-variant/60">
              LangGraph Pipeline
            </span>
            {isRunning && (
              <span className="flex items-center gap-1.5 text-[9px] font-bold text-primary bg-primary/10 border border-primary/20 px-2.5 py-1 rounded-full">
                <span className="w-1.5 h-1.5 rounded-full bg-primary inline-block animate-pulse" />
                LIVE
              </span>
            )}
            {isDone && (
              <span className="text-[9px] font-bold text-tertiary bg-tertiary/10 border border-tertiary/20 px-2.5 py-1 rounded-full">
                COMPLETE
              </span>
            )}
          </div>
          {vulnerableCount > 0 && (
            <span className="text-[10px] font-black text-error bg-error/10 border border-error/20 px-3 py-1 rounded-full">
              취약 {vulnerableCount}건 탐지
            </span>
          )}
        </div>

        {/* 파이프라인 노드 행 */}
        <div className="flex items-start justify-between px-1">
          {NODES.map((node, i) => {
            const isActive = activeNode === node.id && (isRunning || isDone);
            const isFlashing = flashNode === node.id;
            const done = isNodeDone(node.id, phase, isDone);
            const isNextActive = (isRunning || isDone) && activeNode === node.id;

            return (
              <div key={node.id} className="flex items-start flex-1 min-w-0">
                <div className="flex flex-col items-center flex-1 min-w-0 gap-2">
                  {/* 노드 박스 */}
                  <div className="relative">
                    {/* 외부 ping 링 */}
                    {isActive && (
                      <div
                        className="absolute inset-0 rounded-2xl"
                        style={{
                          border: `2px solid ${node.color}`,
                          animation: "ringPing 1.2s ease-out infinite",
                          pointerEvents: "none",
                        }}
                      />
                    )}
                    {/* 두번째 ping 링 (딜레이) */}
                    {isActive && (
                      <div
                        className="absolute inset-0 rounded-2xl"
                        style={{
                          border: `2px solid ${node.color}`,
                          animation: "ringPing 1.2s ease-out 0.4s infinite",
                          pointerEvents: "none",
                        }}
                      />
                    )}

                    {/* 메인 박스 */}
                    <div
                      style={{
                        width: 64,
                        height: 64,
                        borderRadius: "1rem",
                        border: isActive
                          ? `2px solid ${node.color}`
                          : done
                            ? "1px solid rgba(255,255,255,0.15)"
                            : "1px solid rgba(255,255,255,0.05)",
                        background: isActive
                          ? node.bgActive
                          : done
                            ? node.bgDone
                            : "rgba(255,255,255,0.02)",
                        boxShadow: isActive
                          ? `0 0 20px ${node.glow}, 0 0 40px ${node.glowSoft}, inset 0 0 12px ${node.glowSoft}`
                          : "none",
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "center",
                        justifyContent: "center",
                        position: "relative",
                        transition: "all 0.4s cubic-bezier(0.34,1.56,0.64,1)",
                        animation: isFlashing
                          ? "nodeFlash 0.4s ease-out forwards"
                          : isActive && isRunning
                            ? "nodePulse 1.4s ease-in-out infinite"
                            : "none",
                        opacity: !isActive && !done ? 0.35 : 1,
                      }}
                    >
                      <span style={{ fontSize: 24, lineHeight: 1 }}>{node.emoji}</span>

                      {/* 완료 배지 */}
                      {done && !isActive && (
                        <span
                          className="absolute -top-1.5 -right-1.5 w-4 h-4 rounded-full bg-tertiary flex items-center justify-center"
                          style={{ boxShadow: "0 0 6px rgba(52,211,153,0.6)" }}
                        >
                          <span
                            className="material-symbols-outlined text-white"
                            style={{ fontSize: 9, fontVariationSettings: "'FILL' 1" }}
                          >
                            check
                          </span>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* 라벨 */}
                  <div
                    className="text-center"
                    style={{
                      animation: isFlashing ? "labelPop 0.4s ease-out forwards" : "none",
                    }}
                  >
                    <p
                      className="text-[11px] font-black leading-tight transition-all duration-400"
                      style={{
                        color: isActive ? "#ffffff" : done ? "rgba(255,255,255,0.5)" : "rgba(255,255,255,0.2)",
                        textShadow: isActive ? `0 0 10px ${node.color}` : "none",
                      }}
                    >
                      {node.label}
                    </p>
                    <p
                      className="text-[9px] mt-0.5"
                      style={{ color: isActive ? `${node.color}cc` : "rgba(255,255,255,0.2)" }}
                    >
                      {node.sub}
                    </p>

                    {/* 공격 프롬프트 미리보기 */}
                    {node.id === 0 && isActive && latestAttackPrompt && (
                      <div
                        className="mt-1.5 px-1.5 py-1 rounded-lg"
                        style={{
                          maxWidth: 100,
                          background: "rgba(239,68,68,0.08)",
                          border: "1px solid rgba(239,68,68,0.2)",
                        }}
                      >
                        <p className="text-[8px] font-mono text-red-400/80 truncate">
                          {latestAttackPrompt}
                        </p>
                      </div>
                    )}

                    {/* 루프 카운터 */}
                    {node.id === 2 && vulnerableCount > 0 && (
                      <div
                        className="mt-1.5 text-[8px] font-bold px-2 py-0.5 rounded-full"
                        style={{
                          background: isActive ? "rgba(239,68,68,0.2)" : "rgba(239,68,68,0.08)",
                          border: `1px solid rgba(239,68,68,${isActive ? 0.4 : 0.2})`,
                          color: `rgba(239,68,68,${isActive ? 1 : 0.6})`,
                          transition: "all 0.3s",
                        }}
                      >
                        ↺ {vulnerableCount}회
                      </div>
                    )}
                  </div>
                </div>

                {/* 커넥터 화살표 */}
                {i < NODES.length - 1 && (
                  <div className="flex items-center mt-8 mx-0.5 flex-shrink-0">
                    <ConnectorArrow
                      active={isNextActive}
                      done={isNodeDone(node.id, phase, isDone)}
                      color={node.color}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* 루프백 화살표 */}
        {(phase <= 2 || isRunning) && (
          <div className="relative mt-5 px-1">
            <LoopArrow active={loopActive} />
          </div>
        )}

        {/* 하단 상태 */}
        <div className="mt-5 pt-4 border-t border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-2 text-[10px] text-on-surface-variant/50">
            <span className="material-symbols-outlined text-[12px]">swap_horiz</span>
            {completedTests}회 벡터 처리
          </div>
          <div className="text-[10px] text-on-surface-variant/50 font-mono">
            {isDone
              ? "파이프라인 종료"
              : phase <= 2
                ? "Phase 1/2 · 공격 스캔"
                : phase === 3
                  ? "Phase 3 · 방어 생성 중"
                  : "Phase 4 · 검증 중"}
          </div>
        </div>
      </div>
    </>
  );
}

function ConnectorArrow({
  active,
  done,
  color,
}: {
  active: boolean;
  done: boolean;
  color: string;
}) {
  return (
    <div className="relative flex items-center" style={{ width: 36 }}>
      {/* 선 */}
      <div
        className="relative overflow-hidden"
        style={{
          height: active ? 2 : 1,
          width: "100%",
          background: active ? color : done ? "rgba(255,255,255,0.18)" : "rgba(255,255,255,0.05)",
          boxShadow: active ? `0 0 6px ${color}, 0 0 12px ${color}66` : "none",
          borderRadius: 2,
          transition: "all 0.4s ease",
        }}
      >
        {/* 흐르는 파티클 */}
        {active && (
          <div
            style={{
              position: "absolute",
              top: "-2px",
              left: 0,
              width: 10,
              height: 6,
              borderRadius: 3,
              background: `linear-gradient(to right, transparent, ${color}, white, transparent)`,
              animation: "particleFlow 0.65s linear infinite",
            }}
          />
        )}
      </div>
      {/* 화살촉 */}
      <div
        style={{
          width: 0,
          height: 0,
          borderTop: "4px solid transparent",
          borderBottom: "4px solid transparent",
          borderLeft: active
            ? `6px solid ${color}`
            : done
              ? "5px solid rgba(255,255,255,0.2)"
              : "5px solid rgba(255,255,255,0.05)",
          flexShrink: 0,
          filter: active ? `drop-shadow(0 0 4px ${color})` : "none",
          transition: "all 0.4s ease",
        }}
      />
    </div>
  );
}

function LoopArrow({ active }: { active: boolean }) {
  return (
    <div className="relative h-7">
      <svg
        viewBox="0 0 100 28"
        className="absolute left-0 top-0 h-full"
        style={{ width: "62%" }}
        preserveAspectRatio="none"
      >
        <defs>
          <marker
            id="loopArrowHead"
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="5"
            markerHeight="5"
            orient="auto"
          >
            <path
              d="M2 1L8 5L2 9"
              fill="none"
              stroke={active ? "#ef4444" : "rgba(255,255,255,0.15)"}
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </marker>
          {active && (
            <filter id="loopGlow">
              <feGaussianBlur stdDeviation="1.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          )}
        </defs>
        <path
          d="M 92 2 C 92 26, 8 26, 8 2"
          fill="none"
          stroke={active ? "#ef4444" : "rgba(255,255,255,0.1)"}
          strokeWidth={active ? "2" : "1"}
          strokeDasharray={active ? "5 3" : "3 5"}
          markerEnd="url(#loopArrowHead)"
          filter={active ? "url(#loopGlow)" : undefined}
          style={{
            transition: "stroke 0.4s, stroke-width 0.4s",
            animation: active ? "glowBreath 1.4s ease-in-out infinite" : "none",
          }}
        />
        {active && (
          <text x="50" y="25" textAnchor="middle" fontSize="6" fill="rgba(239,68,68,0.7)" fontWeight="bold">
            취약 재공격 루프
          </text>
        )}
      </svg>
    </div>
  );
}
