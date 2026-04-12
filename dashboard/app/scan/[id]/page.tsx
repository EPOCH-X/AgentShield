// [R6] A2 + A3 — 스캔 진행 + 결과 대시보드
// WebSocket /api/v1/scan/{id}/progress
// GET /api/v1/scan/{id}/results
export default function ScanDetailPage({
  params,
}: {
  params: { id: string };
}) {
  // TODO: [R6] 실시간 진행률 + 취약점 맵 + 결과 테이블
  return (
    <div>
      <h1>스캔 결과: {params.id}</h1>
      {/* TODO: [R6] 구현 */}
    </div>
  );
}
