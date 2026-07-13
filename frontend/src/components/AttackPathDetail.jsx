import GraphCanvas from "./GraphCanvas";

export default function AttackPathDetail({ query, graph, onNodeClick }) {
  if (!query) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 text-sm text-slate-400">
        Select an attack query to inspect details.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="mb-1 flex items-center gap-2">
          <span className="text-sm font-semibold text-slate-100">{query.name}</span>
          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">{query.mitre_technique}</span>
          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">{query.mitre_tactic}</span>
        </div>
        <p className="mb-2 text-xs text-slate-400">{query.description}</p>
        <div className="rounded border border-red-700/40 bg-red-900/20 px-3 py-2 text-xs text-red-300">
          Remediation: {query.remediation}
        </div>
      </div>

      <GraphCanvas
        graphData={{ nodes: graph?.nodes || [], edges: graph?.edges || [] }}
        attackPathGraph={graph}
        selectedAttack={query.id}
        onNodeClick={onNodeClick}
      />
    </div>
  );
}
