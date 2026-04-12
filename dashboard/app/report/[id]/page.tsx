// [R6] A4 — 보고서 뷰어 + PDF 다운로드
// GET /api/v1/report/{id}/pdf
export default function ReportPage({
  params,
}: {
  params: { id: string };
}) {
  // TODO: [R6] HTML 보고서 미리보기 + PDF 다운로드 버튼
  return (
    <div>
      <h1>보고서: {params.id}</h1>
      {/* TODO: [R6] 구현 */}
    </div>
  );
}
