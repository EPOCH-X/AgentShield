interface FrrData {
  total_legitimate_requests: number;
  false_refusals: number;
  frr_percentage: number;
}

export function FrrGauge({ data }: { data: FrrData }) {
  // frr_percentage 없으면 frr_rate(0~1)에서 계산, 그것도 없으면 0
  const pct =
    data.frr_percentage != null
      ? data.frr_percentage
      : (data as unknown as { frr_rate?: number }).frr_rate != null
      ? ((data as unknown as { frr_rate: number }).frr_rate * 100)
      : 0;

  const color =
    pct > 15 ? "text-red-500" : pct > 5 ? "text-yellow-500" : "text-green-500";

  return (
    <div className="rounded-lg border p-4 bg-white shadow-sm">
      <h3 className="text-sm font-medium text-gray-500">오탐률 (FRR)</h3>
      <p className={`text-3xl font-bold mt-1 ${color}`}>
        {pct.toFixed(1)}%
      </p>
      <p className="text-xs text-gray-400 mt-1">
        정상 요청 {data.total_legitimate_requests}건 중 {data.false_refusals}건 오탐
      </p>
      <div className="mt-2 text-xs text-gray-400">
        ✅ 5% 미만: 양호 &nbsp;|&nbsp; ⚠️ 5~15%: 주의 &nbsp;|&nbsp; ❌ 15%+: 위험
      </div>
    </div>
  );
}
