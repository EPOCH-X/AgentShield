"use client";

import { useState } from "react";
import DashboardLayout from "../../components/DashboardLayout";

export default function VisualizationPage() {
  const [isFullscreen, setIsFullscreen] = useState(false);

  return (
    <DashboardLayout>
      <main className="h-[calc(100vh-4rem)] bg-[#030711]">
        <div
          className={`bg-[#030711] ${
            isFullscreen ? "fixed inset-0 z-[9999] h-screen w-screen" : "relative h-full w-full"
          }`}
        >
          <iframe
            title="AgentShield 파이프라인 시각화"
            src="/visualization/redblue_pipline_final.html"
            className="h-full w-full border-0"
            allow="autoplay; fullscreen"
          />
          <button
            type="button"
            onClick={() => setIsFullscreen((value) => !value)}
            className="absolute bottom-6 right-6 z-20 rounded-full border border-primary/40 bg-[#061523]/85 px-4 py-2 text-xs font-black text-primary shadow-[0_0_18px_rgba(14,165,165,0.22)] backdrop-blur transition-all hover:-translate-y-0.5 hover:border-primary/70 hover:bg-primary/15"
          >
            {isFullscreen ? "닫기" : "전체보기"}
          </button>
        </div>
      </main>
    </DashboardLayout>
  );
}
