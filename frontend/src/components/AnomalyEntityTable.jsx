function truncate(str, max = 48) {
  if (!str) return "—";
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

export default function AnomalyEntityTable({ findings }) {
  if (!findings?.length) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-slate-500">
        No flagged entities for this run.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Flagged Entities</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">ARN</th>
              <th className="px-4 py-3">Score</th>
              <th className="px-4 py-3">NN</th>
              <th className="px-4 py-3">Drift</th>
              <th className="px-4 py-3">Attack Type</th>
              <th className="px-4 py-3">Window</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((row) => (
              <tr key={`${row.id}-${row.principal_arn}`} className="border-t border-slate-800 text-slate-300">
                <td className="px-4 py-3 font-mono text-xs" title={row.principal_arn}>
                  {truncate(row.principal_arn, 56)}
                </td>
                <td className="px-4 py-3 text-red-400">{row.final_score?.toFixed(4)}</td>
                <td className="px-4 py-3">{row.nn_score?.toFixed(4)}</td>
                <td className="px-4 py-3">{row.drift_score?.toFixed(4)}</td>
                <td className="px-4 py-3">{row.attack_type || "—"}</td>
                <td className="px-4 py-3 text-xs text-slate-500">
                  {row.window_start ? new Date(row.window_start).toLocaleString() : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
