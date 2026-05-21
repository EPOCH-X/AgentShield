"use client";

import { useState } from "react";
import { apiFetch } from "../lib/api";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  blocked?: boolean;
  stage?: string;
  severity?: string;
  reason?: string;
}

interface ChatResponse {
  content?: string;
  blocked?: boolean;
  stage?: string;
  severity?: string;
  reason?: string;
  detail?: string;
}

interface MonitoringChatPanelProps {
  /** 메시지 1건이 처리(차단/허용)될 때마다 부모가 violations 목록을 새로고침. */
  onMessageProcessed?: () => void;
}

const DEFAULT_TARGET_URL = process.env.NEXT_PUBLIC_TESTBED_CHAT_URL || "http://127.0.0.1:8010/chat";

const STAGE_LABEL: Record<string, string> = {
  p1_confidential_scan: "P1 · 기밀 누출",
  p2_inappropriate_use: "P2 · 부적절 사용",
  p3_rate_limit:        "P3 · Rate Limit",
  p4_intent_review:     "P4 · 의도 검토",
  skeleton:             "통과",
};

const SEVERITY_COLOR: Record<string, string> = {
  high:   "#ef4444",
  medium: "#f97316",
  low:    "#eab308",
};

export default function MonitoringChatPanel({ onMessageProcessed }: MonitoringChatPanelProps) {
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    const text = input.trim();
    if (!text || loading) return;

    setMessages((prev) => [...prev, { role: "user", content: text }]);
    setInput("");
    setLoading(true);

    try {
      const res = await apiFetch("/api/v1/monitoring/chat", {
        method: "POST",
        body: JSON.stringify({
          messages: [...messages, { role: "user", content: text }],
          target_url: DEFAULT_TARGET_URL,
        }),
      });
      const data: ChatResponse = await res.json().catch(() => ({}));

      if (!res.ok) {
        setMessages((prev) => [...prev, {
          role: "assistant",
          content: data.detail || "요청 실패",
          blocked: true, stage: "error",
        }]);
      } else {
        setMessages((prev) => [...prev, {
          role: "assistant",
          content: data.content || "(빈 응답)",
          blocked: data.blocked,
          stage: data.stage,
          severity: data.severity,
          reason: data.reason || undefined,
        }]);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "네트워크 오류";
      setMessages((prev) => [...prev, { role: "assistant", content: message, blocked: true, stage: "error" }]);
    } finally {
      setLoading(false);
      // 차단/통과 무관하게 usage_log + violation 가능성 있으므로 부모가 목록 새로고침
      onMessageProcessed?.();
    }
  }

  function handleClear() {
    setMessages([]);
  }

  return (
    <div className="flex flex-col h-full rounded-2xl border border-white/8 bg-gradient-to-b from-surface/80 to-surface/40 backdrop-blur-sm overflow-hidden">
      {/* 헤더 */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/8 bg-white/[0.02]">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-base text-primary" style={{ fontVariationSettings: "'FILL' 1" }}>support_agent</span>
          <div>
            <p className="text-xs font-black uppercase tracking-widest text-primary">1:1 모니터링 챗봇</p>
            <p className="text-[10px] text-on-surface-variant/50">입력 → P1~P4 검사 → 로그·위반 기록</p>
          </div>
        </div>
        {messages.length > 0 && (
          <button onClick={handleClear} className="text-[10px] text-on-surface-variant/40 hover:text-on-surface-variant px-2 py-1 rounded border border-white/5">
            지우기
          </button>
        )}
      </div>

      {/* 메시지 영역 */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2 min-h-[300px]">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center px-4">
            <span className="material-symbols-outlined text-3xl text-on-surface-variant/20 mb-2">forum</span>
            <p className="text-xs text-on-surface-variant/40 leading-relaxed">
              메시지를 입력하면 P1~P4 정책 검사를 거쳐<br/>
              사용 로그와 위반(있는 경우)이<br/>
              좌측 대시보드에 즉시 반영됩니다.
            </p>
          </div>
        ) : (
          messages.map((m, i) => {
            if (m.role === "user") {
              return (
                <div key={i} className="flex justify-end">
                  <div className="max-w-[85%] px-3 py-2 rounded-xl bg-primary/15 border border-primary/25 text-xs text-white leading-relaxed">
                    {m.content}
                  </div>
                </div>
              );
            }
            const sevColor = m.severity ? SEVERITY_COLOR[m.severity] || "#94a3b8" : "#94a3b8";
            return (
              <div key={i} className="flex justify-start">
                <div className="max-w-[85%] space-y-1.5">
                  {m.blocked && m.stage && (
                    <div className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest" style={{ color: sevColor }}>
                      <span className="material-symbols-outlined text-xs" style={{ fontVariationSettings: "'FILL' 1" }}>block</span>
                      {STAGE_LABEL[m.stage] || m.stage} · 차단됨
                    </div>
                  )}
                  <div
                    className="px-3 py-2 rounded-xl text-xs leading-relaxed border whitespace-pre-wrap break-words"
                    style={{
                      background: m.blocked ? `${sevColor}1a` : "rgba(255,255,255,0.04)",
                      borderColor: m.blocked ? `${sevColor}44` : "rgba(255,255,255,0.08)",
                      color: m.blocked ? sevColor : "rgba(255,255,255,0.85)",
                    }}
                  >
                    {m.content}
                  </div>
                  {m.reason && (
                    <p className="text-[10px] text-on-surface-variant/45 px-1 leading-relaxed">
                      <span className="font-bold">근거: </span>{m.reason}
                    </p>
                  )}
                </div>
              </div>
            );
          })
        )}
        {loading && (
          <div className="flex justify-start">
            <div className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs text-on-surface-variant/60 animate-pulse">
              검사 중…
            </div>
          </div>
        )}
      </div>

      {/* 입력 폼 */}
      <form onSubmit={handleSend} className="border-t border-white/8 p-3 bg-white/[0.02]">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="메시지 입력 후 Enter"
            disabled={loading}
            className="flex-1 px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-xs text-white placeholder:text-on-surface-variant/30 focus:outline-none focus:border-primary/40"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="px-3 py-2 rounded-lg bg-primary/20 border border-primary/30 text-primary text-xs font-bold disabled:opacity-30 disabled:cursor-not-allowed hover:bg-primary/30 transition-colors"
          >
            <span className="material-symbols-outlined text-sm">send</span>
          </button>
        </div>
      </form>
    </div>
  );
}
