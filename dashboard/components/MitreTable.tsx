interface MitreRow {
  category: string;
  failure_mode: string | null;
  primary_technique_id: string;
  primary_technique_name: string;
  tactic: string;
  url: string;
  secondary: { technique_id: string; name: string }[];
}

export function MitreTable({ rows }: { rows: MitreRow[] }) {
  const displayRows = rows.filter((r) => !r.failure_mode);

  return (
    <div className="mt-6">
      <h2 className="text-lg font-semibold mb-3">MITRE ATT&amp;CK 매핑</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="bg-gray-50 text-gray-600">
              <th className="px-3 py-2 text-left border">카테고리</th>
              <th className="px-3 py-2 text-left border">대표 기법</th>
              <th className="px-3 py-2 text-left border">전술(Tactic)</th>
              <th className="px-3 py-2 text-left border">보조 기법</th>
            </tr>
          </thead>
          <tbody>
            {displayRows.map((row) => (
              <tr key={row.category} className="hover:bg-gray-50">
                <td className="px-3 py-2 border font-mono font-semibold text-blue-700">
                  {row.category}
                </td>
                <td className="px-3 py-2 border">
                  <a
                    href={row.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:underline"
                  >
                    {row.primary_technique_id}
                  </a>
                  <span className="text-gray-600 ml-1">— {row.primary_technique_name}</span>
                </td>
                <td className="px-3 py-2 border text-gray-600">{row.tactic}</td>
                <td className="px-3 py-2 border text-gray-500 text-xs">
                  {row.secondary.map((s) => s.technique_id).join(", ") || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-gray-400 mt-2">
        출처: MITRE ATT&amp;CK Enterprise v16 · CyberSecEval 4 (Meta PurpleLlama) 기준
      </p>
    </div>
  );
}
