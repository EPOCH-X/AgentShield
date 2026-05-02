"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { login, setToken, setUsername } from "../../lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsernameState] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const data = await login(username, password);
      setToken(data.access_token);
      setUsername(username);
      sessionStorage.removeItem("intro_done"); // 로그인마다 인트로 재생
      router.replace("/intro");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "로그인에 실패했습니다.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      className="min-h-screen bg-background flex items-center justify-center p-6 relative overflow-hidden"
      style={{
        backgroundImage:
          "radial-gradient(ellipse 80% 60% at 50% -10%, rgba(14,165,165,0.18) 0%, transparent 60%), radial-gradient(ellipse 60% 40% at 80% 80%, rgba(10,114,114,0.10) 0%, transparent 50%), linear-gradient(180deg, #091E30 0%, #071824 100%)",
      }}
    >
      {/* Ambient orbs */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -top-32 left-1/2 -translate-x-1/2 w-[480px] h-[480px] rounded-full bg-primary/10 blur-[100px]" />
        <div className="absolute top-1/2 -left-32 w-64 h-64 rounded-full bg-secondary/8 blur-[80px]" />
        <div className="absolute bottom-0 right-0 w-80 h-80 rounded-full bg-primary/6 blur-[90px]" />
      </div>

      <div className="w-full max-w-[440px] relative z-10">

        {/* ── Hero Logo ── */}
        <div className="flex flex-col items-center mb-8">
          {/* Glow ring behind logo */}
          <div className="relative mb-6">
            <div className="absolute inset-0 rounded-3xl bg-primary/20 blur-2xl scale-110" />
            <div className="absolute inset-0 rounded-3xl ring-1 ring-primary/30 scale-105" />
            <img
              src="/logo3.png"
              alt="AgentShield"
              className="relative w-44 h-44 object-contain rounded-3xl shadow-[0_0_60px_rgba(14,165,165,0.35)]"
            />
          </div>

          <h1 className="text-4xl font-extrabold tracking-tight text-white font-headline">
            AgentShield
          </h1>
          <p className="text-[11px] uppercase tracking-[0.35em] text-primary font-bold mt-2 opacity-80">
            Sentinel Advanced
          </p>
        </div>

        {/* ── Card ── */}
        <div
          className="rounded-3xl p-8 shadow-2xl"
          style={{
            background: "rgba(9, 26, 38, 0.72)",
            backdropFilter: "blur(20px)",
            WebkitBackdropFilter: "blur(20px)",
            border: "1px solid rgba(14, 165, 165, 0.16)",
          }}
        >
          <div className="mb-7">
            <h2 className="text-lg font-bold text-white font-headline">
              보안 콘솔 로그인
            </h2>
            <p className="text-sm text-on-surface-variant/70 mt-1">
              인증된 사용자만 접근 가능합니다.
            </p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            {/* Username */}
            <div className="space-y-1.5">
              <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/80">
                사용자 ID
              </label>
              <div className="relative">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-primary/70 text-[20px]">
                  person
                </span>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsernameState(e.target.value)}
                  required
                  placeholder="아이디를 입력하세요"
                  className="w-full border border-white/8 rounded-2xl pl-12 pr-5 py-3.5 text-sm focus:border-primary/60 focus:ring-2 focus:ring-primary/10 focus:outline-none transition-all placeholder:text-on-surface-variant/60"
                  style={{ color: "#ffffff", backgroundColor: "rgba(255,255,255,0.06)", WebkitTextFillColor: "#ffffff" }}
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/80">
                비밀번호
              </label>
              <div className="relative">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-primary/70 text-[20px]">
                  lock
                </span>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="비밀번호를 입력하세요"
                  className="w-full border border-white/8 rounded-2xl pl-12 pr-5 py-3.5 text-sm focus:border-primary/60 focus:ring-2 focus:ring-primary/10 focus:outline-none transition-all placeholder:text-on-surface-variant/60"
                  style={{ color: "#ffffff", backgroundColor: "rgba(255,255,255,0.06)", WebkitTextFillColor: "#ffffff" }}
                />
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-center gap-3 p-3.5 rounded-2xl bg-error/10 border border-error/20">
                <span className="material-symbols-outlined text-error text-lg flex-shrink-0">
                  error
                </span>
                <p className="text-sm text-error font-medium">{error}</p>
              </div>
            )}

            {/* Submit */}
            <div className="pt-1">
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3.5 rounded-2xl font-extrabold text-sm tracking-[0.08em] uppercase transition-all active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
                style={{
                  background: "linear-gradient(135deg, #0A7272 0%, #0EA5A5 50%, #2DD4D4 100%)",
                  color: "#fff",
                  boxShadow: loading ? "none" : "0 8px 32px rgba(14,165,165,0.40), 0 0 0 1px rgba(14,165,165,0.20)",
                }}
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="w-4 h-4 border-2 border-white/60 border-t-white rounded-full animate-spin" />
                    인증 중...
                  </span>
                ) : (
                  "로그인"
                )}
              </button>
            </div>

            {/* Signup link */}
            <div className="flex items-center justify-center gap-2 pt-1">
              <span className="text-xs text-on-surface-variant/40">
                계정이 없으신가요?
              </span>
              <button
                type="button"
                onClick={() => router.push("/signup")}
                className="text-xs font-bold text-primary hover:text-secondary transition-colors"
              >
                회원가입
              </button>
            </div>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-[10px] text-on-surface-variant/30 mt-6 font-mono uppercase tracking-widest">
          AgentShield © 2025 — All rights reserved
        </p>
      </div>
    </div>
  );
}
