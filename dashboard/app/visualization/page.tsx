"use client";

import DashboardLayout from "../../components/DashboardLayout";

export default function VisualizationPage() {
  return (
    <DashboardLayout>
      <main className="h-[calc(100vh-4rem)] bg-[#030711]">
        <iframe
          title="AgentShield 파이프라인 시각화"
          src="/visualization/redblue_pipline_final.html"
          className="h-full w-full border-0"
          allow="autoplay; fullscreen"
        />
      </main>
    </DashboardLayout>
  );
}
