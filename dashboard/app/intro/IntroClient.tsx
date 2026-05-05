"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";

/* ── 숫자 코드 비 (컬럼별로 색 혼합) ── */
function CodeRain({ bright }: { bright: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const colW = 26, fs = 14;
    let id: number, last = 0;
    // 컬럼별 색상 — teal / emerald / violet 3가지
    const PALETTE = ["#2DD4D4", "#34d399", "#a78bfa"];
    type Col = { y: number; speed: number; active: boolean; color: string };
    let cols: Col[] = [];
    function init() {
      canvas.width = window.innerWidth; canvas.height = window.innerHeight;
      ctx.fillStyle = "#030a10"; ctx.fillRect(0, 0, canvas.width, canvas.height);
      cols = Array.from({ length: Math.floor(canvas.width / colW) }, () => ({
        y: Math.random() * -(canvas.height / fs) * 1.5,
        speed: 0.45 + Math.random() * 0.65,
        active: Math.random() > 0.35,
        color: PALETTE[Math.floor(Math.random() * PALETTE.length)],
      }));
    }
    function draw(ts: number) {
      id = requestAnimationFrame(draw);
      if (ts - last < 55) return; last = ts;
      ctx.fillStyle = "rgba(3,10,16,0.11)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${fs}px 'Share Tech Mono', monospace`;
      cols.forEach((col, i) => {
        if (!col.active) return;
        const headY = col.y * fs;
        if (headY >= 0 && headY <= canvas.height) {
          ctx.shadowBlur = bright ? 14 : 8;
          ctx.shadowColor = col.color;
          ctx.fillStyle = "#e8fffa";
          ctx.fillText(String(Math.floor(Math.random() * 10)), i * colW + 4, headY);
          ctx.shadowBlur = 0;
        }
        col.y += col.speed;
        if (headY > canvas.height + 200) {
          col.y = Math.random() * -(canvas.height / fs);
          col.speed = 0.45 + Math.random() * 0.65;
          col.active = Math.random() > 0.2;
          col.color = PALETTE[Math.floor(Math.random() * PALETTE.length)];
        }
      });
    }
    init();
    window.addEventListener("resize", init);
    id = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(id); window.removeEventListener("resize", init); };
  }, [bright]);
  return <canvas ref={canvasRef} className="absolute inset-0 pointer-events-none"
    style={{ opacity: bright ? 0.65 : 0.38, transition: "opacity 1.2s", zIndex: 0 }} />;
}

const SPARKS = [
  { tx:"-110px", ty:"-110px", angle:-45  },
  { tx:"0px",    ty:"-140px", angle:-90  },
  { tx:"110px",  ty:"-110px", angle:-135 },
  { tx:"140px",  ty:"0px",    angle:180  },
  { tx:"110px",  ty:"110px",  angle:135  },
  { tx:"0px",    ty:"140px",  angle:90   },
  { tx:"-110px", ty:"110px",  angle:45   },
  { tx:"-140px", ty:"0px",    angle:0    },
  { tx:"-70px",  ty:"-130px", angle:-110 },
  { tx:"70px",   ty:"-130px", angle:-70  },
];
// 스파크 색상 — teal, emerald, amber 섞기
const SPARK_COLORS = ["#2DD4D4","#34d399","#fbbf24","#ffffff","#a78bfa","#2DD4D4","#34d399","#fbbf24","#ffffff","#2DD4D4"];

type Phase = "dark"|"shield"|"scanning"|"unlock"|"flash"|"granted"|"title"|"exit";

export default function IntroClient() {
  const router = useRouter();
  const [phase, setPhase]             = useState<Phase>("dark");
  const [fadingOut, setFadingOut]     = useState(false);
  const [screenFlash, setScreenFlash] = useState(false);
  const [clawSlash, setClawSlash]     = useState(false);
  const [glitching, setGlitching]     = useState(false);

  useEffect(() => {
    if (sessionStorage.getItem("intro_done") === "1") {
      router.replace("/scan"); return;
    }
    const t = [
      setTimeout(() => setPhase("shield"),   400),
      setTimeout(() => setPhase("scanning"), 1400),
      setTimeout(() => {
        setClawSlash(true);
        setTimeout(() => setScreenFlash(true),  200);
        setTimeout(() => setScreenFlash(false), 580);
        setTimeout(() => setClawSlash(false),   900);
      }, 2800),
      setTimeout(() => setPhase("unlock"),   3750),
      setTimeout(() => setPhase("flash"),    3980),
      setTimeout(() => setPhase("granted"),  4500),
      setTimeout(() => {
        setGlitching(true);
        setTimeout(() => setGlitching(false), 600);
      }, 4600),
      setTimeout(() => setPhase("title"),    5300),
      setTimeout(() => { setPhase("exit"); setFadingOut(true); }, 6400),
      setTimeout(() => {
        sessionStorage.setItem("intro_done", "1");
        router.replace("/scan");
      }, 7500),
    ];
    return () => t.forEach(clearTimeout);
  }, [router]);

  const shieldVisible  = ["shield","scanning","unlock","flash","granted","title","exit"].includes(phase);
  const scanVisible    = ["scanning","unlock"].includes(phase);
  const unlocked       = ["unlock","flash","granted","title","exit"].includes(phase);
  const flashActive    = phase === "flash";
  const grantedVisible = ["granted","title","exit"].includes(phase);
  const titleVisible   = ["title","exit"].includes(phase);

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: `
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Share+Tech+Mono&display=swap');

        @keyframes shieldDraw {
          from { stroke-dashoffset: 400; opacity: 0.2; }
          to   { stroke-dashoffset: 0;   opacity: 1; }
        }
        @keyframes scanLine {
          from { top: 8%;  opacity: 1; }
          to   { top: 92%; opacity: 0.2; }
        }
        @keyframes lockSlide {
          from { transform: translateY(0)   rotate(0deg); }
          to   { transform: translateY(-7px) rotate(-22deg); }
        }
        @keyframes shieldFlash {
          0%   { filter: drop-shadow(0 0 8px #0ea5a5)  drop-shadow(0 0 0px #a78bfa);  transform: scale(1); }
          25%  { filter: drop-shadow(0 0 60px #2DD4D4) drop-shadow(0 0 80px #a78bfa); transform: scale(1.14); }
          60%  { filter: drop-shadow(0 0 30px #34d399);                               transform: scale(1.07); }
          100% { filter: drop-shadow(0 0 18px #2DD4D4);                               transform: scale(1.05); }
        }
        @keyframes ringExpand {
          from { transform: scale(0.8); opacity: 1; }
          to   { transform: scale(2.8); opacity: 0; }
        }
        @keyframes screenBurst {
          0%   { opacity: 0; }
          18%  { opacity: 0.9; }
          100% { opacity: 0; }
        }
        @keyframes sparkOut {
          0%   { transform: translate(0,0) scale(1.2); opacity: 1; }
          60%  { opacity: 0.8; }
          100% { transform: translate(var(--tx),var(--ty)) scale(0); opacity: 0; }
        }
        @keyframes glitchR {
          0%,100% { clip-path: inset(40% 0 50% 0); transform: translate(-4px,0); opacity:0.8; }
          33%     { clip-path: inset(10% 0 75% 0); transform: translate(4px,0); }
          66%     { clip-path: inset(70% 0 10% 0); transform: translate(-2px,0); }
        }
        @keyframes glitchB {
          0%,100% { clip-path: inset(60% 0 20% 0); transform: translate(4px,0); opacity:0.8; }
          33%     { clip-path: inset(20% 0 60% 0); transform: translate(-4px,0); }
          66%     { clip-path: inset(5%  0 85% 0); transform: translate(2px,0); }
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
          0%,100% { opacity: 0.55; }
          50%     { opacity: 1; }
        }
        /* 발톱 */
        @keyframes clawSwoop {
          0%   {
            transform: translate(90%, -110%) rotate(20deg) scale(1.1);
            opacity: 0;
            filter: blur(10px) drop-shadow(0 0 30px rgba(45,212,212,1));
          }
          12%  {
            opacity: 1;
            filter: blur(4px) drop-shadow(0 0 25px rgba(45,212,212,0.9));
          }
          40%  {
            transform: translate(0%, 0%) rotate(5deg) scale(1);
            opacity: 1;
            filter: blur(0) drop-shadow(0 0 20px rgba(45,212,212,0.7));
          }
          65%  {
            transform: translate(-12%, 14%) rotate(2deg) scale(0.97);
            opacity: 0.6;
          }
          100% {
            transform: translate(-25%, 28%) rotate(-2deg) scale(0.92);
            opacity: 0;
          }
        }
        @keyframes impactFlare {
          0%   { transform: scale(0.4); opacity: 0; }
          22%  { opacity: 1; transform: scale(1); }
          100% { transform: scale(2.6); opacity: 0; }
        }
        @keyframes scratchDraw {
          0%   { stroke-dashoffset: 400; opacity: 0; }
          6%   { opacity: 1; }
          55%  { stroke-dashoffset: 0; opacity: 0.9; }
          80%  { stroke-dashoffset: 0; opacity: 0.45; }
          100% { stroke-dashoffset: 0; opacity: 0; }
        }
      `}} />

      <div className="fixed inset-0 flex flex-col items-center justify-center overflow-hidden"
        style={{ background: "#030a10", zIndex: 9999 }}>

        {/* 코드 비 */}
        <CodeRain bright={unlocked} />

        {/* 스캔라인 오버레이 */}
        <div className="absolute inset-0 pointer-events-none" style={{
          backgroundImage: "repeating-linear-gradient(0deg, rgba(45,212,212,0.016) 0px, rgba(45,212,212,0.016) 1px, transparent 1px, transparent 4px)",
          animation: "scanlineScroll 3s linear infinite", zIndex: 1,
        }} />

        {/* 중앙 비네트 */}
        <div className="absolute inset-0 pointer-events-none" style={{
          background: "radial-gradient(ellipse 55% 60% at 50% 50%, rgba(3,10,16,0.72) 0%, transparent 100%)",
          zIndex: 2,
        }} />

        {/* 코너 HUD — 각 모서리 다른 색 */}
        {([
          ["top-5 left-5 border-t-2 border-l-2 rounded-tl-lg",    "rgba(45,212,212,0.5)"],
          ["top-5 right-5 border-t-2 border-r-2 rounded-tr-lg",   "rgba(167,139,250,0.5)"],
          ["bottom-5 left-5 border-b-2 border-l-2 rounded-bl-lg", "rgba(52,211,153,0.5)"],
          ["bottom-5 right-5 border-b-2 border-r-2 rounded-br-lg","rgba(251,191,36,0.45)"],
        ] as [string, string][]).map(([cls, color], i) => (
          <div key={i} className={`absolute w-8 h-8 ${cls}`}
            style={{ borderColor: color, zIndex: 2 }} />
        ))}

        {/* ══ 발톱 이미지 슬래시 ══ */}
        {clawSlash && (
          <div className="absolute inset-0 pointer-events-none" style={{ zIndex: 14 }}>
            {/* 임팩트 플레어 — 방패 중심 */}
            <div className="absolute" style={{
              left:"50%", top:"45%", width:200, height:200, marginLeft:-100, marginTop:-100,
              borderRadius:"50%",
              background:"radial-gradient(circle, rgba(255,255,255,0.9) 0%, rgba(45,212,212,0.55) 25%, rgba(45,212,212,0.2) 55%, transparent 75%)",
              animation:"impactFlare 0.65s 0.25s ease-out both",
              opacity:0,
            }} />
            {/* 발톱 이미지 */}
            <div className="absolute inset-0 flex items-center justify-center" style={{ marginTop: "-6%" }}>
              <img
                src="/claw.png"
                alt=""
                draggable={false}
                style={{
                  width: 700,
                  height: "auto",
                  animation: "clawSwoop 0.88s cubic-bezier(0.22, 0.61, 0.36, 1) forwards",
                  filter: "drop-shadow(0 0 18px rgba(45,212,212,0.85)) drop-shadow(0 0 40px rgba(45,212,212,0.4)) brightness(1.1)",
                  userSelect: "none",
                }}
              />
            </div>
            {/* 긁힌 자국 — 발톱 지나간 뒤 뒤따라 그려짐 */}
            <svg viewBox="0 0 100 100" preserveAspectRatio="none"
              style={{ position:"absolute", inset:0, width:"100%", height:"100%", overflow:"visible" }}>
              {[
                { x1:78, y1:2,  x2:22, y2:90, w:0.55, delay:0.30, color:"#2DD4D4",            glow:"rgba(45,212,212,0.8)" },
                { x1:83, y1:2,  x2:27, y2:90, w:0.9,  delay:0.34, color:"#ffffff",            glow:"rgba(45,212,212,0.6)" },
                { x1:88, y1:2,  x2:32, y2:90, w:1.1,  delay:0.38, color:"#ffffff",            glow:"rgba(45,212,212,0.6)" },
                { x1:93, y1:2,  x2:37, y2:90, w:0.9,  delay:0.42, color:"#ffffff",            glow:"rgba(45,212,212,0.6)" },
                { x1:98, y1:2,  x2:42, y2:90, w:0.55, delay:0.46, color:"#2DD4D4",            glow:"rgba(45,212,212,0.8)" },
              ].map((s, i) => (
                <line key={i}
                  x1={s.x1} y1={s.y1} x2={s.x2} y2={s.y2}
                  stroke={s.color} strokeWidth={s.w} strokeLinecap="round"
                  style={{
                    strokeDasharray: 400,
                    strokeDashoffset: 400,
                    filter: `drop-shadow(0 0 2px ${s.glow}) drop-shadow(0 0 6px ${s.glow})`,
                    animation: `scratchDraw 0.55s ${s.delay}s cubic-bezier(0.4,0,0.2,1) forwards`,
                  }}
                />
              ))}
            </svg>
          </div>
        )}

        {/* 화면 번쩍 — amber+emerald 톤 */}
        {screenFlash && (
          <div className="absolute inset-0 pointer-events-none" style={{
            background:"radial-gradient(ellipse 75% 65% at 50% 46%, rgba(255,255,255,0.22) 0%, rgba(251,191,36,0.3) 20%, rgba(52,211,153,0.15) 50%, transparent 75%)",
            animation:"screenBurst 0.4s ease-out forwards", zIndex:13,
          }} />
        )}

        {/* ══ 방패 ══ */}
        <div className="relative flex flex-col items-center gap-8" style={{ zIndex: 5 }}>
          <div className="relative flex items-center justify-center" style={{ width:260, height:285 }}>

            {/* 스파크 */}
            {flashActive && SPARKS.map((s, i) => (
              <div key={i} style={{
                position:"absolute", left:"50%", top:"50%",
                width: i%3===0 ? 3 : 2, height: i%3===0 ? 24 : 15,
                marginLeft:-1, marginTop:-8, borderRadius:2,
                background:`linear-gradient(to bottom, #ffffff, ${SPARK_COLORS[i]})`,
                // @ts-ignore
                "--tx":s.tx, "--ty":s.ty,
                transform:`rotate(${s.angle}deg)`, transformOrigin:"center bottom",
                animation:`sparkOut 0.65s ${i*0.03}s cubic-bezier(0.25,0.46,0.45,0.94) forwards`,
                filter:"blur(0.5px)",
                boxShadow:`0 0 6px ${SPARK_COLORS[i]}`,
              }} />
            ))}

            {/* 링 확장 */}
            {flashActive && [
              { d:0,    c:"#2DD4D4",            w:2 },
              { d:0.12, c:"rgba(167,139,250,0.6)", w:1 },
              { d:0.24, c:"rgba(52,211,153,0.5)",  w:1 },
            ].map((r, i) => (
              <div key={i} className="absolute rounded-full" style={{
                width:230, height:230,
                border:`${r.w}px solid ${r.c}`,
                animation:`ringExpand 0.8s ${r.d}s ease-out forwards`,
              }} />
            ))}
            {!flashActive && shieldVisible && (
              <div className="absolute rounded-full" style={{
                width:230, height:230,
                border:`1px solid rgba(${unlocked?"45,212,212":"14,165,165"},0.22)`,
                animation:"ringExpand 2s ease-out infinite",
              }} />
            )}

            {/* 방패 SVG */}
            {shieldVisible && (
              <svg viewBox="0 0 100 115" width={230} height={264} style={{
                opacity: shieldVisible ? 1 : 0,
                transition:"opacity 0.4s",
                animation: flashActive ? "shieldFlash 0.75s ease-out forwards" : undefined,
                filter: unlocked && !flashActive
                  ? "drop-shadow(0 0 16px rgba(45,212,212,0.8)) drop-shadow(0 0 6px rgba(167,139,250,0.4))"
                  : shieldVisible
                    ? "drop-shadow(0 0 6px rgba(14,165,165,0.35))"
                    : "none",
              }}>
                <defs>
                  <linearGradient id="scanGrad" x1="0" x2="1">
                    <stop offset="0%"   stopColor="transparent" />
                    <stop offset="50%"  stopColor="#fbbf24" stopOpacity="0.9" />
                    <stop offset="100%" stopColor="transparent" />
                  </linearGradient>
                  <linearGradient id="shieldGrad" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%"   stopColor={unlocked ? "#2DD4D4" : "#0ea5a5"} />
                    <stop offset="100%" stopColor={unlocked ? "#a78bfa" : "#0ea5a5"} />
                  </linearGradient>
                </defs>

                {/* 방패 면 */}
                <path d="M50 4 L92 18 L92 56 Q92 88 50 108 Q8 88 8 56 L8 18 Z"
                  fill={unlocked ? "rgba(45,212,212,0.10)" : "rgba(14,165,165,0.06)"}
                  style={{ transition:"fill 0.5s" }} />
                {/* 외곽선 — gradient */}
                <path d="M50 4 L92 18 L92 56 Q92 88 50 108 Q8 88 8 56 L8 18 Z"
                  fill="none" stroke="url(#shieldGrad)" strokeWidth="2.5"
                  strokeLinecap="round" strokeLinejoin="round" strokeDasharray="400"
                  style={{ animation:"shieldDraw 0.9s cubic-bezier(0.4,0,0.2,1) forwards", transition:"stroke 0.5s" }} />
                {/* 내부선 */}
                <path d="M50 14 L82 25 L82 54 Q82 78 50 96 Q18 78 18 54 L18 25 Z"
                  fill="none"
                  stroke={unlocked ? "rgba(167,139,250,0.4)" : "rgba(14,165,165,0.2)"}
                  strokeWidth="1" strokeDasharray="300"
                  style={{ animation:"shieldDraw 1.1s 0.2s cubic-bezier(0.4,0,0.2,1) forwards", transition:"stroke 0.5s" }} />

                {/* 자물쇠 */}
                <g transform="translate(50,58)">
                  <rect x="-14" y="-4" width="28" height="22" rx="4"
                    fill={unlocked ? "rgba(52,211,153,0.2)" : "rgba(14,165,165,0.16)"}
                    stroke={unlocked ? "#34d399" : "#0ea5a5"} strokeWidth="2"
                    style={{ transition:"all 0.4s" }} />
                  <path d="M -8 -4 L -8 -14 Q -8 -24 0 -24 Q 8 -24 8 -14 L 8 -4"
                    fill="none"
                    stroke={unlocked ? "#34d399" : "#0ea5a5"} strokeWidth="2.5" strokeLinecap="round"
                    style={{ transformOrigin:"8px -14px", transition:"stroke 0.4s",
                      animation: unlocked ? "lockSlide 0.4s ease-out forwards" : "none" }} />
                  <circle cx="0" cy="7" r={unlocked ? "3.5" : "3"}
                    fill={unlocked ? "#34d399" : "#0ea5a5"}
                    style={{ transition:"all 0.4s" }} />
                  {unlocked && (
                    <rect x="-1.5" y="7" width="3" height="7" rx="1" fill="#34d399"
                      style={{ animation:"titleIn 0.3s ease-out forwards" }} />
                  )}
                </g>

                {/* 스캔 라인 — amber */}
                {scanVisible && (
                  <rect x="8" y="0" width="84" height="2.5" fill="url(#scanGrad)"
                    style={{ animation:"scanLine 1.2s ease-in-out forwards" }} />
                )}
              </svg>
            )}

            {/* glow 반사 */}
            {unlocked && (
              <div className="absolute bottom-0 left-1/2 -translate-x-1/2" style={{
                width:170, height:36,
                background:"radial-gradient(ellipse, rgba(52,211,153,0.35) 0%, transparent 70%)",
                animation:"titleIn 0.5s ease-out forwards",
              }} />
            )}
          </div>

          {/* 텍스트 영역 — 고정 높이로 방패 위치 고정 */}
          <div style={{ position:"relative", width:500, height:130 }}>

            {/* 스캔 중 — amber 텍스트 */}
            {scanVisible && (
              <div style={{
                position:"absolute", inset:0, display:"flex", alignItems:"center", justifyContent:"center",
                fontFamily:"'Share Tech Mono', monospace", fontSize:13,
                letterSpacing:"0.4em", textTransform:"uppercase",
                color: phase === "unlock" ? "#34d399" : "#fbbf24",
                animation:"scanPulse 0.7s ease-in-out infinite",
                transition:"color 0.5s",
              }}>
                {phase === "unlock" ? "VERIFYING IDENTITY..." : "AUTHENTICATING..."}
              </div>
            )}

            {/* ACCESS GRANTED + 타이틀 — 같은 절대 컨테이너에서 순서대로 */}
            {grantedVisible && (
              <div style={{ position:"absolute", inset:0, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", gap:12 }}>
                <div style={{ position:"relative" }}>
                  <div style={{
                    fontFamily:"'Orbitron', sans-serif", fontSize:44, fontWeight:900,
                    color:"#34d399", letterSpacing:"0.18em", whiteSpace:"nowrap",
                    textShadow:"0 0 20px rgba(52,211,153,0.9), 0 0 55px rgba(52,211,153,0.4), 0 0 90px rgba(52,211,153,0.15)",
                    animation:"grantedIn 0.8s cubic-bezier(0.34,1.56,0.64,1) forwards",
                  }}>ACCESS GRANTED</div>
                  {glitching && (<>
                    <div style={{ position:"absolute", inset:0,
                      fontFamily:"'Orbitron', sans-serif", fontSize:44, fontWeight:900,
                      color:"#ef4444", letterSpacing:"0.18em", whiteSpace:"nowrap",
                      animation:"glitchR 0.1s steps(1) infinite", opacity:0.7 }}>ACCESS GRANTED</div>
                    <div style={{ position:"absolute", inset:0,
                      fontFamily:"'Orbitron', sans-serif", fontSize:44, fontWeight:900,
                      color:"#a78bfa", letterSpacing:"0.18em", whiteSpace:"nowrap",
                      animation:"glitchB 0.1s steps(1) infinite", opacity:0.7 }}>ACCESS GRANTED</div>
                  </>)}
                </div>
                {titleVisible && (
                  <div style={{ animation:"titleIn 0.6s ease-out forwards", textAlign:"center" }}>
                    <p style={{ fontFamily:"'Orbitron', sans-serif", fontSize:32, fontWeight:700,
                      color:"#ffffff", letterSpacing:"0.12em",
                      textShadow:"0 0 20px rgba(255,255,255,0.25), 0 0 40px rgba(167,139,250,0.3)" }}>
                      AgentShield
                    </p>
                    <p style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:13,
                      letterSpacing:"0.5em", color:"rgba(167,139,250,0.75)",
                      marginTop:6, textTransform:"uppercase" }}>
                      Sentinel Advanced
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* 프로그레스 바 */}
        {shieldVisible && phase !== "exit" && (
          <div className="absolute bottom-10 left-1/2 -translate-x-1/2" style={{ width:220, zIndex:5 }}>
            <div style={{ height:1, background:"rgba(255,255,255,0.07)", borderRadius:2, overflow:"hidden" }}>
              <div style={{
                height:"100%", borderRadius:2,
                background: phase==="scanning"
                  ? "linear-gradient(to right, #fbbf24, #f59e0b)"
                  : phase==="unlock"
                    ? "linear-gradient(to right, #34d399, #2DD4D4)"
                    : "linear-gradient(to right, #2DD4D4, #a78bfa)",
                width: phase==="shield" ? "18%"
                  : phase==="scanning" ? "45%"
                  : phase==="unlock"   ? "68%"
                  : phase==="flash"    ? "88%" : "100%",
                transition:"width 0.8s ease-out, background 0.6s ease",
                boxShadow:"0 0 8px rgba(45,212,212,0.6)",
              }} />
            </div>
            <p style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:9,
              letterSpacing:"0.25em",
              color: phase==="scanning" ? "rgba(251,191,36,0.5)"
                : phase==="unlock" ? "rgba(52,211,153,0.5)"
                : "rgba(167,139,250,0.5)",
              textAlign:"center", marginTop:6, textTransform:"uppercase",
              transition:"color 0.5s" }}>
              {phase==="shield"   ? "INITIALIZING..."
                : phase==="scanning" ? "SCANNING CREDENTIALS..."
                : phase==="unlock"   ? "VERIFYING IDENTITY..."
                : phase==="flash"    ? "UNLOCKING SYSTEM..."
                : "SYSTEM ARMED"}
            </p>
          </div>
        )}

        {/* 페이드아웃 */}
        <div className="absolute inset-0 pointer-events-none" style={{
          background:"#000", opacity: fadingOut ? 1 : 0,
          transition: fadingOut ? "opacity 1s ease-in-out" : "none",
          zIndex:30,
        }} />
      </div>
    </>
  );
}
