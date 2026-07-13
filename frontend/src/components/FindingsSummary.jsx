/**
 * Four cards: Total Open | Critical+High | Frameworks Affected | New This Scan.
 */
export default function FindingsSummary({ summary }) {
  if (!summary) {
    return (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="rounded-lg border border-slate-200 bg-slate-50 p-4">
            <div className="h-6 animate-pulse rounded bg-slate-200" />
            <div className="mt-2 h-8 w-16 animate-pulse rounded bg-slate-200" />
          </div>
        ))}
      </div>
    );
  }

  const totalCriticalHigh =
    (summary.by_severity?.CRITICAL || 0) + (summary.by_severity?.HIGH || 0);
  const frameworkCount = summary.by_framework ? Object.keys(summary.by_framework).length : 0;

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        <p className="text-sm font-medium text-slate-500">Total Open</p>
        <p className="mt-1 text-2xl font-semibold text-slate-800">{summary.total_open ?? 0}</p>
      </div>
      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        <p className="text-sm font-medium text-slate-500">Critical + High</p>
        <p className="mt-1 text-2xl font-semibold text-orange-600">{totalCriticalHigh}</p>
      </div>
      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        <p className="text-sm font-medium text-slate-500">Frameworks Affected</p>
        <p className="mt-1 text-2xl font-semibold text-slate-800">{frameworkCount}</p>
      </div>
      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        <p className="text-sm font-medium text-slate-500">New This Scan</p>
        <p className="mt-1 text-2xl font-semibold text-blue-600">{summary.new_this_run ?? 0}</p>
      </div>
    </div>
  );
}
