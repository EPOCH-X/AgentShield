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
      router.replace("/scan");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "로그인에 실패했습니다.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      className="min-h-screen bg-background flex items-center justify-center p-4"
      style={{
        backgroundImage:
          "radial-gradient(circle at 50% 0%, #0d1c32 0%, #041329 100%)",
      }}
    >
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-10">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-primary to-primary-container flex items-center justify-center shadow-lg shadow-primary/30 neon-glow-primary mb-5">
            <span
              className="material-symbols-outlined text-on-primary-container text-3xl"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              security
            </span>
          </div>
          <h1 className="text-3xl font-extrabold tracking-tighter text-white font-headline">
            AgentShield
          </h1>
          <p className="text-[11px] uppercase tracking-[0.3em] text-primary/70 font-bold mt-1">
            SENTINEL ADVANCED
          </p>
        </div>

        {/* Card */}
        <div className="glass-panel rounded-[2rem] p-8 shadow-2xl">
          <div className="mb-8">
            <h2 className="text-xl font-bold text-on-surface font-headline">
              보안 콘솔 로그인
            </h2>
            <p className="text-sm text-on-surface-variant mt-1">
              인증된 사용자만 접근 가능합니다.
            </p>
          </div>

          <form onSubmit={handleLogin} className="space-y-5">
            {/* Username */}
            <div className="space-y-2">
              <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                사용자 ID
              </label>
              <div className="relative">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40 text-lg">
                  person
                </span>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsernameState(e.target.value)}
                  required
                  placeholder="아이디를 입력하세요"
                  className="w-full bg-white/5 border border-white/10 rounded-2xl pl-12 pr-5 py-4 text-sm focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all placeholder:text-on-surface-variant/30"
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-2">
              <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                비밀번호
              </label>
              <div className="relative">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40 text-lg">
                  lock
                </span>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="비밀번호를 입력하세요"
                  className="w-full bg-white/5 border border-white/10 rounded-2xl pl-12 pr-5 py-4 text-sm focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all placeholder:text-on-surface-variant/30"
                />
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-center gap-3 p-4 rounded-2xl bg-error/10 border border-error/20">
                <span className="material-symbols-outlined text-error text-lg">
                  error
                </span>
                <p className="text-sm text-error font-medium">{error}</p>
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-4 rounded-[1.25rem] bg-gradient-to-r from-primary via-[#4DA8FF] to-primary-container text-on-primary-container font-extrabold text-sm tracking-[0.1em] uppercase shadow-[0_10px_30px_rgba(0,163,255,0.3)] hover:shadow-[0_15px_40px_rgba(0,163,255,0.4)] hover:-translate-y-0.5 transition-all active:scale-[0.98] active:translate-y-0 neon-glow-primary disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-4 h-4 border-2 border-on-primary-container border-t-transparent rounded-full animate-spin" />
                  인증 중...
                </span>
              ) : (
                "로그인"
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-[10px] text-on-surface-variant/40 mt-6 font-mono uppercase tracking-widest">
          AgentShield © 2025 — All rights reserved
        </p>
      </div>
    </div>
  );
}
