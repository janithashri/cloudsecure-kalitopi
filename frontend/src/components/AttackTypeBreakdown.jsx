export default function AttackTypeBreakdown({ paperComparison = [], perAttackMetrics = {} }) {
  const rows = paperComparison.length
    ? paperComparison
    : Object.entries(perAttackMetrics).map(([attackType, metrics]) => ({
        attack_type: attackType,
        paper_f1: 0.74,
        our_f1: metrics.f1_score,
        paper_fpr: 0.09,
        our_fpr: metrics.false_positive_rate,
      }));

  if (!rows.length) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-slate-500">
        No per-attack-type metrics yet.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Paper Comparison</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">Attack Type</th>
              <th className="px-4 py-3">Paper F1</th>
              <th className="px-4 py-3">Our F1</th>
              <th className="px-4 py-3">Paper FPR</th>
              <th className="px-4 py-3">Our FPR</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.attack_type} className="border-t border-slate-800 text-slate-300">
                <td className="px-4 py-3">{row.attack_type}</td>
                <td className="px-4 py-3">{(row.paper_f1 ?? 0).toFixed(2)}</td>
                <td className="px-4 py-3 text-blue-400">{(row.our_f1 ?? 0).toFixed(2)}</td>
                <td className="px-4 py-3">{(row.paper_fpr ?? 0).toFixed(2)}</td>
                <td className="px-4 py-3 text-blue-400">{(row.our_fpr ?? 0).toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
