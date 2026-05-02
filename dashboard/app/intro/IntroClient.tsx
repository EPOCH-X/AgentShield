"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";

/* ── 숫자 코드 비 ── */
function CodeRain({ opacity = 0.5 }: { opacity?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const colW = 26, fontSize = 14;
    let animId: number, lastTime = 0;
    type Col = { y: number; speed: number; active: boolean };
    let cols: Col[] = [];
    function init() {
      canvas.width = window.innerWidth; canvas.height = window.innerHeight;
      ctx.fillStyle = "#030a10"; ctx.fillRect(0, 0, canvas.width, canvas.height);
      cols = Array.from({ length: Math.floor(canvas.width / colW) }, () => ({
        y: Math.random() * -(canvas.height / fontSize) * 1.5,
        speed: 0.5 + Math.random() * 0.6,
        active: Math.random() > 0.35,
      }));
    }
    function draw(ts: number) {
      animId = requestAnimationFrame(draw);
      if (ts - lastTime < 55) return;
      lastTime = ts;
      ctx.fillStyle = "rgba(3,10,16,0.12)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${fontSize}px 'Share Tech Mono', monospace`;
      cols.forEach((col, i) => {
        if (!col.active) return;
        const headY = col.y * fontSize;
        if (headY >= 0 && headY <= canvas.height) {
          ctx.shadowBlur = 10; ctx.shadowColor = "#2DD4D4";
          ctx.fillStyle = "#e0fffe";
          ctx.fillText(String(Math.floor(Math.random() * 10)), i * colW + 4, headY);
          ctx.shadowBlur = 0;
        }
        col.y += col.speed;
        if (headY > canvas.height + 200) {
          col.y = Math.random() * -(canvas.height / fontSize);
          col.speed = 0.5 + Math.random() * 0.6;
          col.active = Math.random() > 0.2;
        }
      });
    }
    init();
    window.addEventListener("resize", init);
    animId = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(animId); window.removeEventListener("resize", init); };
  }, []);
  return <canvas ref={canvasRef} className="absolute inset-0 pointer-events-none"
    style={{ opacity, transition: "opacity 1.2s ease-in-out", zIndex: 0 }} />;
}

/* ── 스파크 방향 정의 ── */
const SPARKS = [
  { tx: "-110px", ty: "-110px", angle: -45 },
  { tx: "0px",    ty: "-140px", angle: -90 },
  { tx: "110px",  ty: "-110px", angle: -135 },
  { tx: "140px",  ty: "0px",    angle: 180 },
  { tx: "110px",  ty: "110px",  angle: 135 },
  { tx: "0px",    ty: "140px",  angle: 90 },
  { tx: "-110px", ty: "110px",  angle: 45 },
  { tx: "-140px", ty: "0px",    angle: 0 },
  { tx: "-70px",  ty: "-130px", angle: -110 },
  { tx: "70px",   ty: "-130px", angle: -70 },
];

type Phase = "dark" | "scanning" | "unlock" | "flash" | "granted" | "title" | "exit";

export default function IntroClient() {
  const router = useRouter();
  const [phase, setPhase]           = useState<Phase>("dark");
  const [fadingOut, setFadingOut]   = useState(false);
  const [screenFlash, setScreenFlash] = useState(false);
  const [clawSlash, setClawSlash]   = useState(false);
  const [glitching, setGlitching]   = useState(false);
  const [logoShatter, setLogoShatter] = useState(false);

  useEffect(() => {
    if (sessionStorage.getItem("intro_done") === "1") {
      router.replace("/scan"); return;
    }
    const t = [
      setTimeout(() => setPhase("scanning"), 600),    // 로고 홀로그램 등장
      setTimeout(() => setPhase("unlock"),   2800),    // 인증 완료 직전
      // 표범 발톱이 쥐 방패를 할퀸다
      setTimeout(() => {
        setClawSlash(true);
        setTimeout(() => setScreenFlash(true),  200);
        setTimeout(() => setScreenFlash(false), 600);
        setTimeout(() => setLogoShatter(true),  280);  // 로고 폭발
        setTimeout(() => setClawSlash(false),   900);
      }, 3400),
      setTimeout(() => setPhase("flash"),    3700),
      setTimeout(() => setPhase("granted"),  4300),
      setTimeout(() => { setGlitching(true); setTimeout(() => setGlitching(false), 600); }, 4400),
      setTimeout(() => setPhase("title"),    5100),
      setTimeout(() => { setPhase("exit"); setFadingOut(true); }, 6200),
      setTimeout(() => { sessionStorage.setItem("intro_done", "1"); router.replace("/scan"); }, 7300),
    ];
    return () => t.forEach(clearTimeout);
  }, [router]);

  const logoVisible    = ["scanning", "unlock"].includes(phase);
  const unlocked       = ["unlock","flash","granted","title","exit"].includes(phase);
  const shieldVisible  = ["flash","granted","title","exit"].includes(phase);
  const flashActive    = phase === "flash";
  const grantedVisible = ["granted","title","exit"].includes(phase);
  const titleVisible   = ["title","exit"].includes(phase);

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: `
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Share+Tech+Mono&display=swap');

        @keyframes shieldDraw {
          from { stroke-dashoffset: 400; opacity: 0.2; }
          to   { stroke-dashoffset: 0; opacity: 1; }
        }
        @keyframes lockSlide {
          from { transform: translateY(0) rotate(0deg); }
          to   { transform: translateY(-7px) rotate(-22deg); }
        }
        @keyframes shieldFlash {
          0%   { filter: drop-shadow(0 0 8px #0ea5a5); transform: scale(1); }
          25%  { filter: drop-shadow(0 0 80px #0ea5a5) drop-shadow(0 0 140px #2DD4D4); transform: scale(1.14); }
          60%  { filter: drop-shadow(0 0 35px #0ea5a5); transform: scale(1.07); }
          100% { filter: drop-shadow(0 0 18px #0ea5a5); transform: scale(1.05); }
        }
        @keyframes ringExpand {
          from { transform: scale(0.8); opacity: 1; }
          to   { transform: scale(2.8); opacity: 0; }
        }
        @keyframes screenBurst {
          0%   { opacity: 0; }
          20%  { opacity: 0.85; }
          100% { opacity: 0; }
        }
        @keyframes sparkOut {
          0%   { transform: translate(0,0) scale(1.2); opacity: 1; }
          60%  { opacity: 0.8; }
          100% { transform: translate(var(--tx), var(--ty)) scale(0); opacity: 0; }
        }
        @keyframes glitchR {
          0%,100% { clip-path: inset(40% 0 50% 0); transform: translate(-4px,0); opacity:0.8; }
          33%     { clip-path: inset(10% 0 75% 0); transform: translate(4px,0); }
          66%     { clip-path: inset(70% 0 10% 0); transform: translate(-2px,0); }
        }
        @keyframes glitchB {
          0%,100% { clip-path: inset(60% 0 20% 0); transform: translate(4px,0); opacity:0.8; }
          33%     { clip-path: inset(20% 0 60% 0); transform: translate(-4px,0); }
          66%     { clip-path: inset(5% 0 85% 0); transform: translate(2px,0); }
        }
        @keyframes scanlineScroll {
          from { background-position: 0 0; }
          to   { background-position: 0 100px; }
        }
        @keyframes grantedIn {
          from { letter-spacing: 0.5em; opacity: 0; filter: blur(10px); }
          to   { letter-spacing: 0.18em; opacity: 1; filter: blur(0); }
        }
        @keyframes titleIn {
          from { opacity: 0; transform: translateY(12px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes scanPulse {
          0%,100% { opacity: 0.6; }
          50%     { opacity: 1; }
        }

        /* 홀로그램 로고 패널 */
        @keyframes holoIn {
          from { opacity: 0; transform: translateY(20px) scale(0.94); }
          to   { opacity: 1; transform: translateY(0) scale(1); }
        }
        @keyframes holoScanBar {
          0%   { top: 0%; }
          100% { top: 100%; }
        }
        @keyframes holoPulse {
          0%,100% { box-shadow: 0 0 24px rgba(14,165,165,0.35), 0 0 60px rgba(14,165,165,0.1); }
          50%     { box-shadow: 0 0 36px rgba(14,165,165,0.6), 0 0 80px rgba(14,165,165,0.2); }
        }
        @keyframes holoShatter {
          0%   { transform: scale(1);   opacity: 1; filter: brightness(1); }
          30%  { transform: scale(1.06); opacity: 1; filter: brightness(3); }
          100% { transform: scale(1.25); opacity: 0; filter: brightness(4) blur(8px); }
        }

        /* 표범 발톱 */
        @keyframes clawCut {
          0%   { stroke-dashoffset: 160; opacity: 0; }
          6%   { opacity: 1; }
          40%  { stroke-dashoffset: 0; opacity: 1; }
          68%  { stroke-dashoffset: 0; opacity: 0.6; }
          100% { stroke-dashoffset: 0; opacity: 0; }
        }
        @keyframes impactFlare {
          0%   { transform: scale(0.4); opacity: 0; }
          20%  { opacity: 1; transform: scale(1); }
          100% { transform: scale(2.5); opacity: 0; }
        }
        @keyframes clawScratch {
          0%   { opacity: 0; }
          15%  { opacity: 0.8; }
          60%  { opacity: 0.5; }
          100% { opacity: 0; }
        }
      `}} />

      <div className="fixed inset-0 flex flex-col items-center justify-center overflow-hidden"
        style={{ background: "#030a10", zIndex: 9999 }}>

        {/* 숫자 코드 비 */}
        <CodeRain opacity={shieldVisible ? 0.7 : 0.4} />

        {/* 스캔라인 전체 오버레이 */}
        <div className="absolute inset-0 pointer-events-none" style={{
          backgroundImage: "repeating-linear-gradient(0deg, rgba(14,165,165,0.018) 0px, rgba(14,165,165,0.018) 1px, transparent 1px, transparent 4px)",
          animation: "scanlineScroll 3s linear infinite", zIndex: 1,
        }} />

        {/* 중앙 비네트 */}
        <div className="absolute inset-0 pointer-events-none" style={{
          background: "radial-gradient(ellipse 60% 65% at 50% 50%, rgba(3,10,16,0.7) 0%, transparent 100%)",
          zIndex: 2,
        }} />

        {/* 코너 HUD */}
        {["top-5 left-5 border-t-2 border-l-2 rounded-tl-lg","top-5 right-5 border-t-2 border-r-2 rounded-tr-lg",
          "bottom-5 left-5 border-b-2 border-l-2 rounded-bl-lg","bottom-5 right-5 border-b-2 border-r-2 rounded-br-lg"
        ].map((cls, i) => (
          <div key={i} className={`absolute w-8 h-8 ${cls}`}
            style={{ borderColor: "rgba(14,165,165,0.4)", zIndex: 2 }} />
        ))}

        {/* ══ 홀로그램 로고 패널 ══ */}
        {(logoVisible || logoShatter) && (
          <div className="absolute flex flex-col items-center" style={{
            zIndex: 6,
            top: "50%", left: "50%",
            transform: "translate(-50%, -54%)",
            animation: logoShatter
              ? "holoShatter 0.45s ease-out forwards"
              : "holoIn 0.7s cubic-bezier(0.34,1.2,0.64,1) forwards",
          }}>
            {/* 패널 외곽 */}
            <div style={{
              position: "relative",
              width: 240, height: 240,
              borderRadius: 20,
              overflow: "hidden",
              border: "1px solid rgba(14,165,165,0.5)",
              animation: !logoShatter ? "holoPulse 2s ease-in-out infinite" : undefined,
            }}>
              {/* 로고 이미지 — 다크 배경 위에 */}
              <div style={{ width: "100%", height: "100%", background: "#060f18" }}>
                <img src="/logo3.png" alt="AgentShield"
                  style={{ width: "100%", height: "100%", objectFit: "contain",
                    filter: "brightness(0.82) saturate(1.3) contrast(1.05)" }} />
              </div>

              {/* 홀로그램 teal 색조 */}
              <div style={{
                position: "absolute", inset: 0,
                background: "linear-gradient(160deg, rgba(14,165,165,0.10) 0%, rgba(45,212,212,0.06) 50%, rgba(14,165,165,0.12) 100%)",
              }} />

              {/* 스캔 라인 */}
              <div style={{
                position: "absolute", inset: 0,
                backgroundImage: "repeating-linear-gradient(0deg, rgba(45,212,212,0.06) 0px, rgba(45,212,212,0.06) 1px, transparent 1px, transparent 3px)",
                animation: "scanlineScroll 1.5s linear infinite",
              }} />

              {/* 움직이는 스캔 바 */}
              <div style={{
                position: "absolute", left: 0, right: 0, height: 2,
                background: "linear-gradient(90deg, transparent, rgba(45,212,212,0.7), transparent)",
                animation: "holoScanBar 1.8s ease-in-out infinite",
              }} />

              {/* 하단 그라데이션 */}
              <div style={{
                position: "absolute", bottom: 0, left: 0, right: 0, height: 60,
                background: "linear-gradient(to top, rgba(3,10,16,0.5), transparent)",
              }} />
            </div>

            {/* 패널 하단 텍스트 */}
            <div style={{
              marginTop: 12,
              fontFamily: "'Share Tech Mono', monospace",
              fontSize: 10, letterSpacing: "0.35em",
              color: "rgba(14,165,165,0.7)", textTransform: "uppercase",
              animation: "scanPulse 1.2s ease-in-out infinite",
            }}>
              {phase === "unlock" ? "VERIFYING AGENT..." : "SCANNING CREDENTIALS..."}
            </div>
          </div>
        )}

        {/* ══ 표범 발톱 슬래시 — 쥐 방패를 정조준 ══ */}
        {clawSlash && (
          <div className="absolute inset-0 pointer-events-none" style={{ zIndex: 14 }}>

            {/* 임팩트 플레어 — 로고 중앙 (쥐 방패 위치) */}
            <div className="absolute" style={{
              left: "50%", top: "47%",
              width: 160, height: 160,
              marginLeft: -80, marginTop: -80,
              borderRadius: "50%",
              background: "radial-gradient(circle, rgba(255,255,255,0.95) 0%, rgba(45,212,212,0.7) 30%, rgba(14,165,165,0.2) 60%, transparent 75%)",
              animation: "impactFlare 0.6s ease-out forwards",
            }} />

            {/* 발톱 5줄 SVG — 우측에서 쥐 방패(~50%, 68%) 정조준 */}
            <svg viewBox="0 0 100 100" preserveAspectRatio="none"
              style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }}>
              {[
                // x1(시작-오른쪽), y1, x2(끝-쥐방패 근처), y2, 두께, 딜레이, 투명도
                { x1: 91, y1: 14, x2: 27, y2: 58, w: 0.22, d: 0,    a: 0.65 },
                { x1: 95, y1: 22, x2: 34, y2: 64, w: 0.42, d: 0.05, a: 0.88 },
                { x1: 98, y1: 30, x2: 41, y2: 70, w: 0.55, d: 0.10, a: 1.0  },
                { x1: 100,y1: 38, x2: 47, y2: 76, w: 0.42, d: 0.15, a: 0.88 },
                { x1: 100,y1: 46, x2: 53, y2: 82, w: 0.22, d: 0.20, a: 0.65 },
              ].map((c, i) => (
                <g key={i}>
                  {/* 메인 발톱 선 */}
                  <line x1={c.x1} y1={c.y1} x2={c.x2} y2={c.y2}
                    stroke="white" strokeWidth={c.w} strokeLinecap="round"
                    style={{
                      strokeDasharray: 160, strokeDashoffset: 160,
                      opacity: c.a,
                      filter: "drop-shadow(0 0 1px #2DD4D4) drop-shadow(0 0 3px #0ea5a5)",
                      animation: `clawCut 0.8s ${c.d}s cubic-bezier(0.15,0.7,0.3,1) forwards`,
                    }}
                  />
                  {/* 안쪽 하이라이트 (중간 3줄만) */}
                  {i >= 1 && i <= 3 && (
                    <line x1={c.x1 + 0.3} y1={c.y1} x2={c.x2 + 0.3} y2={c.y2}
                      stroke="rgba(200,255,255,0.85)" strokeWidth={0.1} strokeLinecap="round"
                      style={{
                        strokeDasharray: 160, strokeDashoffset: 160,
                        animation: `clawCut 0.8s ${c.d}s cubic-bezier(0.15,0.7,0.3,1) forwards`,
                      }}
                    />
                  )}
                </g>
              ))}

              {/* 발톱 흔적 — 긁힌 자국 (선보다 조금 지속) */}
              {[34, 41, 47].map((x2, i) => (
                <line key={`scratch-${i}`}
                  x1={[95,98,100][i]} y1={[22,30,38][i]} x2={x2} y2={[64,70,76][i]}
                  stroke={`rgba(45,212,212,0.${4-i})`} strokeWidth={0.08} strokeLinecap="round"
                  style={{ animation: `clawScratch 1.1s ${0.25}s ease-out forwards` }}
                />
              ))}
            </svg>
          </div>
        )}

        {/* 발톱 임팩트 화면 번쩍 */}
        {screenFlash && (
          <div className="absolute inset-0 pointer-events-none" style={{
            background: "radial-gradient(ellipse 70% 60% at 50% 48%, rgba(255,255,255,0.2) 0%, rgba(45,212,212,0.4) 25%, rgba(14,165,165,0.1) 55%, transparent 75%)",
            animation: "screenBurst 0.4s ease-out forwards",
            zIndex: 13,
          }} />
        )}

        {/* ══ 방패 + 잠금 (flash 이후) ══ */}
        <div className="relative flex flex-col items-center gap-6" style={{ zIndex: 7 }}>
          {shieldVisible && (
            <div className="relative flex items-center justify-center" style={{ width: 200, height: 220 }}>

              {/* 스파크 */}
              {flashActive && SPARKS.map((s, i) => (
                <div key={i} style={{
                  position: "absolute", left: "50%", top: "50%",
                  width: i % 3 === 0 ? 3 : 2, height: i % 3 === 0 ? 22 : 14,
                  marginLeft: -1, marginTop: -8, borderRadius: 2,
                  background: i % 2 === 0
                    ? "linear-gradient(to bottom, #ffffff, #2DD4D4)"
                    : "linear-gradient(to bottom, #2DD4D4, transparent)",
                  // @ts-ignore
                  "--tx": s.tx, "--ty": s.ty,
                  transform: `rotate(${s.angle}deg)`, transformOrigin: "center bottom",
                  animation: `sparkOut 0.6s ${i * 0.03}s cubic-bezier(0.25,0.46,0.45,0.94) forwards`,
                  filter: "blur(0.5px)", boxShadow: "0 0 6px rgba(45,212,212,0.8)",
                }} />
              ))}

              {/* 링 확장 */}
              {flashActive && [0, 0.1, 0.22].map((delay, i) => (
                <div key={i} className="absolute rounded-full" style={{
                  width: 180, height: 180,
                  border: `${i === 0 ? 2 : 1}px solid ${i === 0 ? "#2DD4D4" : "rgba(14,165,165,0.5)"}`,
                  animation: `ringExpand 0.75s ${delay}s ease-out forwards`,
                }} />
              ))}
              {!flashActive && (
                <div className="absolute rounded-full" style={{
                  width: 180, height: 180,
                  border: "1px solid rgba(14,165,165,0.25)",
                  animation: "ringExpand 2s ease-out infinite",
                }} />
              )}

              {/* 방패 SVG */}
              <svg viewBox="0 0 100 115" width={180} height={207} style={{
                animation: flashActive ? "shieldFlash 0.7s ease-out forwards"
                  : "titleIn 0.5s ease-out forwards",
                filter: "drop-shadow(0 0 18px rgba(14,165,165,0.75))",
              }}>
                <defs>
                  <linearGradient id="scanGrad" x1="0" x2="1">
                    <stop offset="0%" stopColor="transparent" />
                    <stop offset="50%" stopColor="#2DD4D4" stopOpacity="0.95" />
                    <stop offset="100%" stopColor="transparent" />
                  </linearGradient>
                </defs>
                <path d="M50 4 L92 18 L92 56 Q92 88 50 108 Q8 88 8 56 L8 18 Z"
                  fill="rgba(14,165,165,0.13)" />
                <path d="M50 4 L92 18 L92 56 Q92 88 50 108 Q8 88 8 56 L8 18 Z"
                  fill="none" stroke="#2DD4D4" strokeWidth="2.5"
                  strokeLinecap="round" strokeLinejoin="round" strokeDasharray="400"
                  style={{ animation: "shieldDraw 0.9s cubic-bezier(0.4,0,0.2,1) forwards" }} />
                <path d="M50 14 L82 25 L82 54 Q82 78 50 96 Q18 78 18 54 L18 25 Z"
                  fill="none" stroke="rgba(45,212,212,0.35)" strokeWidth="1" strokeDasharray="300"
                  style={{ animation: "shieldDraw 1.1s 0.2s cubic-bezier(0.4,0,0.2,1) forwards" }} />
                {/* 자물쇠 해제 */}
                <g transform="translate(50, 58)">
                  <rect x="-14" y="-4" width="28" height="22" rx="4"
                    fill="rgba(45,212,212,0.22)" stroke="#2DD4D4" strokeWidth="2" />
                  <path d="M -8 -4 L -8 -14 Q -8 -24 0 -24 Q 8 -24 8 -14 L 8 -4"
                    fill="none" stroke="#2DD4D4" strokeWidth="2.5" strokeLinecap="round"
                    style={{ transformOrigin: "8px -14px", animation: "lockSlide 0.4s 0.3s ease-out forwards" }} />
                  <circle cx="0" cy="7" r="3.5" fill="#2DD4D4" />
                  <rect x="-1.5" y="7" width="3" height="7" rx="1" fill="#2DD4D4"
                    style={{ animation: "titleIn 0.3s 0.5s ease-out forwards", opacity: 0 }} />
                </g>
              </svg>

              {/* glow 반사 */}
              <div className="absolute bottom-0 left-1/2 -translate-x-1/2" style={{
                width: 130, height: 30,
                background: "radial-gradient(ellipse, rgba(14,165,165,0.4) 0%, transparent 70%)",
                animation: "titleIn 0.5s ease-out forwards",
              }} />
            </div>
          )}

          {/* 텍스트 */}
          <div className="flex flex-col items-center gap-4 text-center">
            {/* ACCESS GRANTED */}
            {grantedVisible && (
              <div style={{ position: "relative" }}>
                <div style={{
                  fontFamily: "'Orbitron', sans-serif", fontSize: 38, fontWeight: 900,
                  color: "#2DD4D4", letterSpacing: "0.18em",
                  textShadow: "0 0 24px rgba(45,212,212,0.9), 0 0 60px rgba(45,212,212,0.5)",
                  animation: "grantedIn 0.8s cubic-bezier(0.34,1.56,0.64,1) forwards",
                }}>ACCESS GRANTED</div>
                {glitching && (<>
                  <div style={{ position:"absolute", inset:0, fontFamily:"'Orbitron', sans-serif",
                    fontSize:38, fontWeight:900, color:"#ef4444", letterSpacing:"0.18em",
                    animation:"glitchR 0.1s steps(1) infinite", opacity:0.7 }}>ACCESS GRANTED</div>
                  <div style={{ position:"absolute", inset:0, fontFamily:"'Orbitron', sans-serif",
                    fontSize:38, fontWeight:900, color:"#60a5fa", letterSpacing:"0.18em",
                    animation:"glitchB 0.1s steps(1) infinite", opacity:0.7 }}>ACCESS GRANTED</div>
                </>)}
              </div>
            )}
            {/* 타이틀 */}
            {titleVisible && (
              <div style={{ animation: "titleIn 0.6s ease-out forwards", textAlign: "center" }}>
                <p style={{ fontFamily:"'Orbitron', sans-serif", fontSize:26, fontWeight:700,
                  color:"#ffffff", letterSpacing:"0.12em",
                  textShadow:"0 0 20px rgba(255,255,255,0.3)" }}>AgentShield</p>
                <p style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:11,
                  letterSpacing:"0.5em", color:"rgba(14,165,165,0.75)", marginTop:6,
                  textTransform:"uppercase" }}>Sentinel Advanced</p>
              </div>
            )}
          </div>
        </div>

        {/* 하단 프로그레스 바 */}
        {phase !== "dark" && phase !== "exit" && (
          <div className="absolute bottom-10 left-1/2 -translate-x-1/2" style={{ width: 220, zIndex: 5 }}>
            <div style={{ height:1, background:"rgba(14,165,165,0.12)", borderRadius:2, overflow:"hidden" }}>
              <div style={{
                height:"100%", borderRadius:2,
                background:"linear-gradient(to right, #0ea5a5, #2DD4D4)",
                width: phase==="scanning" ? "40%"
                  : phase==="unlock" ? "65%"
                  : phase==="flash" ? "88%" : "100%",
                transition:"width 0.8s ease-out",
                boxShadow:"0 0 8px rgba(14,165,165,0.7)",
              }} />
            </div>
            <p style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:9,
              letterSpacing:"0.25em", color:"rgba(14,165,165,0.45)",
              textAlign:"center", marginTop:6, textTransform:"uppercase" }}>
              {phase==="scanning" ? "SCANNING CREDENTIALS..."
                : phase==="unlock" ? "VERIFYING IDENTITY..."
                : phase==="flash" ? "UNLOCKING SYSTEM..."
                : "SYSTEM ARMED"}
            </p>
          </div>
        )}

        {/* 페이드아웃 */}
        <div className="absolute inset-0 pointer-events-none" style={{
          background: "#000",
          opacity: fadingOut ? 1 : 0,
          transition: fadingOut ? "opacity 1s ease-in-out" : "none",
          zIndex: 30,
        }} />
      </div>
    </>
  );
}
