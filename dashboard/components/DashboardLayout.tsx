"use client";

import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { removeToken, getToken } from "../lib/api";

interface DashboardLayoutProps {
  children: React.ReactNode;
}

const navItems = [
  { icon: "security", label: "LLM 보안 스캔", href: "/scan" },
  { icon: "visibility", label: "모니터링 및 위반", href: "/monitoring" },
  { icon: "admin_panel_settings", label: "관리자", href: "/monitoring/admin" },
];

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  const router = useRouter();
  const pathname = usePathname();
  const [username, setUsername] = useState<string>("");

  useEffect(() => {
    setUsername(localStorage.getItem("username") || "Admin");
  }, []);

  function handleLogout() {
    removeToken();
    router.push("/login");
  }

  function isActive(href: string): boolean {
    if (href === "/scan") return pathname === "/scan" || pathname.startsWith("/scan/");
    return pathname === href || (href !== "/" && pathname.startsWith(href));
  }

  return (
    <div className="min-h-screen bg-background text-on-surface">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-full flex flex-col w-64 border-r border-white/5 bg-[#0E0819] backdrop-blur-md shadow-2xl z-50 font-headline tracking-tight text-sm">
        <div className="p-8 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-primary-container flex items-center justify-center shadow-lg shadow-primary/20 neon-glow-primary">
            <span
              className="material-symbols-outlined text-on-primary-container font-bold text-xl"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              security
            </span>
          </div>
          <div>
            <h1 className="text-xl font-extrabold tracking-tighter text-[#39FF14]">
              AgentShield
            </h1>
            <p className="text-[9px] uppercase tracking-[0.3em] text-on-surface-variant/70 font-bold">
              SENTINEL ADVANCED
            </p>
          </div>
        </div>

        <nav className="flex-1 px-4 space-y-1 mt-2">
          {navItems.map((item) => {
            const active = isActive(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 ${
                  active
                    ? "text-primary bg-primary/10 border border-primary/20 font-bold shadow-[0_0_15px_rgba(57,255,20,0.08)]"
                    : "text-on-surface-variant hover:bg-surface-container hover:text-white group"
                }`}
              >
                <span
                  className="material-symbols-outlined transition-colors"
                  style={active ? { fontVariationSettings: "'FILL' 1" } : {}}
                >
                  {item.icon}
                </span>
                <span className="font-medium">{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="px-4 py-6 border-t border-white/5 space-y-1">
          <button
            onClick={handleLogout}
            className="flex items-center gap-3 px-4 py-3 rounded-xl text-on-surface-variant hover:text-white transition-colors w-full group"
          >
            <span className="material-symbols-outlined group-hover:text-error transition-colors">
              logout
            </span>
            <span className="font-medium text-xs uppercase tracking-wider">
              로그아웃
            </span>
          </button>
        </div>
      </aside>

      {/* Main */}
      <div className="ml-64 flex flex-col min-h-screen">
        {/* Top Nav */}
        <header className="w-full h-16 sticky top-0 z-40 bg-background/60 backdrop-blur-2xl border-b border-white/5 flex justify-between items-center px-10">
          <div className="flex items-center gap-6 flex-1">
            <div className="relative w-full max-w-lg">
              <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40 text-lg">
                search
              </span>
              <input
                className="w-full bg-white/5 border border-white/5 rounded-full pl-12 pr-6 py-2.5 text-sm focus:border-primary/50 focus:ring-0 focus:outline-none transition-all placeholder:text-on-surface-variant/30"
                placeholder="로그, 위협 또는 자산 검색..."
                type="text"
              />
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-tertiary/5 border border-tertiary/10">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary shadow-[0_0_8px_rgba(57,255,20,0.7)] animate-pulse" />
              <span className="text-[10px] font-bold text-tertiary tracking-[0.15em] uppercase">
                SYSTEM SECURE
              </span>
            </div>

            <div className="flex items-center gap-4">
              <button className="relative text-on-surface-variant/60 hover:text-primary transition-all">
                <span className="material-symbols-outlined">notifications</span>
                <span className="absolute top-0 right-0 w-2 h-2 bg-error rounded-full border-2 border-background" />
              </button>
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <p className="text-sm font-bold text-white">{username || "Admin"}</p>
                  <p className="text-[10px] text-on-surface-variant">Security Lead</p>
                </div>
                <div className="w-9 h-9 rounded-xl bg-surface-container-high border-2 border-primary/10 hover:border-primary/40 transition-colors flex items-center justify-center">
                  <span className="material-symbols-outlined text-primary text-sm">
                    person
                  </span>
                </div>
              </div>
            </div>
          </div>
        </header>

        <div className="flex-1">{children}</div>
      </div>
    </div>
  );
}
