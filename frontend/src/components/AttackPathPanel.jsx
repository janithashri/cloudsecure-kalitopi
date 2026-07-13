const statusColor = (result) => {
  if (!result) return "bg-slate-500";
  return result.violated ? "bg-red-500" : "bg-emerald-500";
};

const groupedByTactic = (queries) =>
  queries.reduce((acc, q) => {
    const k = q.mitre_tactic || "Other";
    if (!acc[k]) acc[k] = [];
    acc[k].push(q);
    return acc;
  }, {});

export default function AttackPathPanel({
  queries,
  results,
  onRunAll,
  onSelectQuery,
  selectedQueryId,
  running,
}) {
  const groups = groupedByTactic(queries || []);
  const doneCount = Object.keys(results || {}).length;
  const total = (queries || []).length;
  const progress = total > 0 ? Math.round((doneCount / total) * 100) : 0;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-200">MITRE ATT&CK Techniques</h3>
        <button
          onClick={onRunAll}
          disabled={running}
          className="rounded bg-emerald-500 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-60"
        >
          {running ? "Running..." : "Run Attack Analysis"}
        </button>
      </div>
      {running && (
        <div className="mb-4">
          <div className="mb-1 text-xs text-slate-400">{progress}% complete</div>
          <div className="h-1.5 rounded bg-slate-800">
            <div className="h-full rounded bg-emerald-500 transition-all" style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      <div className="space-y-4">
        {Object.entries(groups).map(([tactic, items]) => (
          <div key={tactic}>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">{tactic}</h4>
            <div className="space-y-2">
              {items.map((q) => {
                const result = results?.[q.id];
                return (
                  <button
                    key={q.id}
                    onClick={() => onSelectQuery(q.id)}
                    className={`w-full rounded border p-3 text-left transition ${
                      selectedQueryId === q.id
                        ? "border-emerald-500/60 bg-slate-800"
                        : "border-slate-800 bg-slate-900 hover:border-slate-700"
                    }`}
                  >
                    <div className="mb-1 flex items-center gap-2">
                      <span className={`h-2.5 w-2.5 rounded-full ${statusColor(result)}`} />
                      <span className="text-xs text-slate-400">{q.id}</span>
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">{q.mitre_technique}</span>
                      <span className={`ml-auto rounded px-1.5 py-0.5 text-[10px] ${
                        q.severity === "CRITICAL" ? "bg-red-900/50 text-red-300" : "bg-amber-900/50 text-amber-300"
                      }`}>
                        {q.severity}
                      </span>
                    </div>
                    <div className="text-sm text-slate-100">{q.name}</div>
                    <div className="mt-1 text-xs text-slate-500">
                      {!result ? "Not checked" : result.violated ? `Violated (${result.node_count} nodes)` : "Clean"}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
