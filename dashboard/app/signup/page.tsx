"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { register } from "../../lib/api";

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  async function handleSignup(e: React.FormEvent) {
    e.preventDefault();
    setError("");

    if (password !== passwordConfirm) {
      setError("비밀번호가 일치하지 않습니다.");
      return;
    }

    if (password.length < 8) {
      setError("비밀번호는 최소 8자 이상이어야 합니다.");
      return;
    }

    setLoading(true);

    try {
      await register({ email, username, password });
      setSuccess(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "회원가입에 실패했습니다.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      className="min-h-screen bg-background flex items-center justify-center p-4"
      style={{
        backgroundImage:
          "radial-gradient(circle at 50% 0%, #221840 0%, #1A1026 100%)",
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
          {success ? (
            /* 가입 완료 상태 */
            <div className="text-center space-y-6">
              <div className="flex justify-center">
                <div className="w-16 h-16 rounded-full bg-tertiary/10 border border-tertiary/30 flex items-center justify-center">
                  <span
                    className="material-symbols-outlined text-tertiary text-4xl"
                    style={{ fontVariationSettings: "'FILL' 1" }}
                  >
                    check_circle
                  </span>
                </div>
              </div>
              <div>
                <h2 className="text-xl font-bold text-on-surface font-headline">
                  가입이 완료되었습니다
                </h2>
                <p className="text-sm text-on-surface-variant mt-2">
                  계정이 성공적으로 생성되었습니다.
                  <br />
                  로그인 페이지로 이동하여 접속하세요.
                </p>
              </div>
              <button
                onClick={() => router.push("/login")}
                className="w-full py-4 rounded-[1.25rem] bg-gradient-to-r from-primary via-[#57FF35] to-primary-container text-on-primary font-extrabold text-sm tracking-[0.1em] uppercase shadow-[0_10px_30px_rgba(57,255,20,0.3)] hover:shadow-[0_15px_40px_rgba(57,255,20,0.45)] hover:-translate-y-0.5 transition-all active:scale-[0.98] neon-glow-primary"
              >
                로그인 페이지로
              </button>
            </div>
          ) : (
            /* 가입 폼 */
            <>
              <div className="mb-8">
                <h2 className="text-xl font-bold text-on-surface font-headline">
                  계정 생성
                </h2>
                <p className="text-sm text-on-surface-variant mt-1">
                  AgentShield 보안 콘솔 접근 권한을 신청합니다.
                </p>
              </div>

              <form onSubmit={handleSignup} className="space-y-5">
                {/* Email */}
                <div className="space-y-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    이메일
                  </label>
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40 text-lg">
                      mail
                    </span>
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      placeholder="이메일을 입력하세요"
                      className="w-full bg-white/5 border border-white/10 rounded-2xl pl-12 pr-5 py-4 text-sm focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all placeholder:text-on-surface-variant/30"
                    />
                  </div>
                </div>

                {/* Username */}
                <div className="space-y-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    아이디
                  </label>
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40 text-lg">
                      person
                    </span>
                    <input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
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
                      placeholder="8자 이상 입력하세요"
                      className="w-full bg-white/5 border border-white/10 rounded-2xl pl-12 pr-5 py-4 text-sm focus:border-primary/50 focus:ring-4 focus:ring-primary/5 focus:outline-none transition-all placeholder:text-on-surface-variant/30"
                    />
                  </div>
                </div>

                {/* Password Confirm */}
                <div className="space-y-2">
                  <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant/60">
                    비밀번호 확인
                  </label>
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40 text-lg">
                      lock_reset
                    </span>
                    <input
                      type="password"
                      value={passwordConfirm}
                      onChange={(e) => setPasswordConfirm(e.target.value)}
                      required
                      placeholder="비밀번호를 다시 입력하세요"
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
                  className="w-full py-4 rounded-[1.25rem] bg-gradient-to-r from-primary via-[#57FF35] to-primary-container text-on-primary font-extrabold text-sm tracking-[0.1em] uppercase shadow-[0_10px_30px_rgba(57,255,20,0.3)] hover:shadow-[0_15px_40px_rgba(57,255,20,0.45)] hover:-translate-y-0.5 transition-all active:scale-[0.98] active:translate-y-0 neon-glow-primary disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0"
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <span className="w-4 h-4 border-2 border-on-primary border-t-transparent rounded-full animate-spin" />
                      처리 중...
                    </span>
                  ) : (
                    "회원가입"
                  )}
                </button>

                {/* Login link */}
                <div className="flex items-center justify-center gap-2 pt-1">
                  <span className="text-xs text-on-surface-variant/50">
                    이미 계정이 있으신가요?
                  </span>
                  <button
                    type="button"
                    onClick={() => router.push("/login")}
                    className="text-xs font-bold text-primary hover:text-primary/80 transition-colors"
                  >
                    로그인
                  </button>
                </div>
              </form>
            </>
          )}
        </div>

        <p className="text-center text-[10px] text-on-surface-variant/40 mt-6 font-mono uppercase tracking-widest">
          AgentShield © 2025 — All rights reserved
        </p>
      </div>
    </div>
  );
}
