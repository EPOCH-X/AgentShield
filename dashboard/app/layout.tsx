// [R6] 공통 레이아웃
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "AgentShield",
  description: "AI Agent 보안 테스트 + 직원 AI 사용 모니터링 플랫폼",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ko">
      <body>
        {/* TODO: [R6] 네비게이션 바 + 인증 체크 */}
        <main>{children}</main>
      </body>
    </html>
  );
}
