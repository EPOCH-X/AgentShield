"use client";

import { useState } from "react";

interface ChatbotTestModalProps {
  open: boolean;
  onClose: () => void;
}

interface ChatbotResponse {
  content?: string;
  response?: string;
  tool_trace?: unknown[];
  security_mode?: string;
  model?: string;
  error?: string;
  detail?: string;
}

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

const DEFAULT_PROMPT =
  "Please summarize the refund status for order SE-1042 without exposing private data.";

export default function ChatbotTestModal({ open, onClose }: ChatbotTestModalProps) {
  const [prompt, setPrompt] = useState(DEFAULT_PROMPT);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [lastResponse, setLastResponse] = useState<ChatbotResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  if (!open) return null;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const cleanPrompt = prompt.trim();
    if (!cleanPrompt) {
      setError("프롬프트를 입력해 주세요.");
      return;
    }

    setLoading(true);
    setError("");
    setMessages((prev) => [...prev, { role: "user", content: cleanPrompt }]);

    try {
      const res = await fetch("/api/testbed-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: cleanPrompt }),
      });
      const data: ChatbotResponse = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.detail || "챗봇 응답을 가져오지 못했습니다.");
      }

      const answer = String(data.content || data.response || "").trim() || "(빈 응답)";
      setLastResponse(data);
      setMessages((prev) => [...prev, { role: "assistant", content: answer }]);
      setPrompt("");
    } catch (err) {
      const message = err instanceof Error ? err.message : "챗봇 테스트에 실패했습니다.";
      setError(message);
      setMessages((prev) => [...prev, { role: "assistant", content: `[오류] ${message}` }]);
    } finally {
      setLoading(false);
    }
  }

  const toolTrace = Array.isArray(lastResponse?.tool_trace) ? lastResponse.tool_trace : [];

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center overflow-y-auto overscroll-contain bg-black/70 backdrop-blur-sm p-6">
      <div className="my-6 w-full max-w-5xl max-h-[calc(100vh-3rem)] overflow-hidden rounded-[2rem] border border-primary/20 bg-[#061523] shadow-[0_24px_80px_rgba(0,0,0,0.65)]">
        <div className="flex items-start justify-between gap-6 border-b border-white/10 px-7 py-5">
          <div>
            <div className="flex items-center gap-2 text-primary text-xs font-black tracking-[0.18em] uppercase">
              <span className="material-symbols-outlined text-base">forum</span>
              TESTBED CHAT
            </div>
            <h3 className="mt-2 text-2xl font-extrabold font-headline text-on-surface">
              챗봇 테스트
            </h3>
            <p className="mt-1 text-sm text-on-surface-variant/75">
              Docker 테스트베드 챗봇에 한 문장 프롬프트를 보내 응답을 확인합니다.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-10 h-10 rounded-xl border border-white/10 bg-white/5 text-on-surface-variant hover:text-white hover:border-primary/30 transition-all"
            aria-label="챗봇 테스트 닫기"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        <div className="grid h-[min(680px,calc(100vh-160px))] min-h-0 grid-cols-1 xl:grid-cols-[1fr_320px]">
          <div className="flex min-h-0 flex-col">
            <div className="flex-1 overflow-y-auto overscroll-contain px-7 py-6 space-y-4">
              {messages.length === 0 ? (
                <div className="h-full min-h-[320px] flex flex-col items-center justify-center text-center">
                  <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center">
                    <span className="material-symbols-outlined text-3xl text-primary">chat</span>
                  </div>
                  <p className="mt-5 text-lg font-bold text-on-surface">한 문장 프롬프트를 입력해 주세요.</p>
                  <p className="mt-2 text-sm text-on-surface-variant/65 max-w-md">
                    전체 스캔 전, 타겟 챗봇이 실제로 어떤 응답을 반환하는지 바로 확인할 수 있습니다.
                  </p>
                </div>
              ) : (
                messages.map((message, index) => (
                  <div
                    key={`${message.role}-${index}`}
                    className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}
                  >
                    <div
                      className={`max-w-[78%] max-h-[42vh] overflow-y-auto overscroll-contain rounded-2xl px-5 py-4 text-sm leading-relaxed border ${
                        message.role === "user"
                          ? "bg-primary/15 border-primary/25 text-on-surface"
                          : "bg-white/5 border-white/10 text-on-surface-variant"
                      }`}
                    >
                      <div className="mb-2 text-[10px] uppercase tracking-[0.18em] font-black text-primary/80">
                        {message.role === "user" ? "사용자" : "테스트베드 챗봇"}
                      </div>
                      <div className="whitespace-pre-wrap break-words">{message.content}</div>
                    </div>
                  </div>
                ))
              )}
            </div>

            <form onSubmit={handleSubmit} className="border-t border-white/10 p-5">
              <div className="flex gap-3">
                <input
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  disabled={loading}
                  className="flex-1 rounded-2xl border border-white/10 bg-white/5 px-5 py-3.5 text-sm text-on-surface placeholder:text-on-surface-variant/35 focus:outline-none focus:ring-4 focus:ring-primary/10 focus:border-primary/45 disabled:opacity-60"
                  placeholder="테스트할 프롬프트 한 문장을 입력하세요."
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="rounded-2xl bg-primary px-6 py-3.5 text-sm font-extrabold text-on-primary shadow-[0_8px_24px_rgba(14,165,165,0.28)] transition-all hover:-translate-y-0.5 hover:shadow-[0_12px_30px_rgba(14,165,165,0.42)] disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {loading ? "전송 중..." : "전송"}
                </button>
              </div>
              {error && (
                <p className="mt-3 flex items-center gap-2 text-xs text-error">
                  <span className="material-symbols-outlined text-sm">error</span>
                  {error}
                </p>
              )}
            </form>
          </div>

          <aside className="min-h-0 overflow-y-auto overscroll-contain border-t xl:border-t-0 xl:border-l border-white/10 bg-black/15 p-5 space-y-5">
            <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-[10px] font-black uppercase tracking-[0.18em] text-on-surface-variant/55">
                연결 대상
              </p>
              <p className="mt-2 font-mono text-xs text-primary break-all">http://localhost:8010/chat</p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                <p className="text-[10px] font-black uppercase tracking-[0.18em] text-on-surface-variant/55">
                  모델
                </p>
                <p className="mt-2 text-xs text-on-surface break-words">
                  {lastResponse?.model || "응답 후 표시"}
                </p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                <p className="text-[10px] font-black uppercase tracking-[0.18em] text-on-surface-variant/55">
                  보안 모드
                </p>
                <p className="mt-2 text-xs text-on-surface">
                  {lastResponse?.security_mode || "응답 후 표시"}
                </p>
              </div>
            </div>

            <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-[10px] font-black uppercase tracking-[0.18em] text-on-surface-variant/55">
                  도구 호출
                </p>
                <span className="rounded-full border border-primary/20 bg-primary/10 px-2 py-1 text-[10px] font-bold text-primary">
                  {toolTrace.length}건
                </span>
              </div>
              {toolTrace.length > 0 ? (
                <pre className="mt-3 max-h-72 overflow-auto rounded-xl bg-black/35 p-3 text-[11px] leading-relaxed text-on-surface-variant">
                  {JSON.stringify(toolTrace, null, 2)}
                </pre>
              ) : (
                <p className="mt-3 text-xs text-on-surface-variant/65">도구 호출 없음</p>
              )}
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
