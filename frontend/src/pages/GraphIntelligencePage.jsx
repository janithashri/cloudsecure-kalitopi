import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { getGraphIntelligence, runGraphAnalysis } from "../api/graphIntelligence";

const severityColors = {
  CRITICAL: "bg-red-500/10 text-red-400",
  HIGH: "bg-orange-500/10 text-orange-400",
  MEDIUM: "bg-yellow-500/10 text-yellow-400",
  LOW: "bg-blue-500/10 text-blue-400",
  INFO: "bg-slate-500/10 text-slate-400",
};

const reasonLabels = {
  high_centrality: "High centrality",
  chokepoint: "Chokepoint",
  internet_exposed: "Internet exposed",
  large_blast_radius: "Large blast radius",
  dense_zone: "Dense zone",
  bridge_node: "Bridge node",
};

function truncate(str, max = 42) {
  if (!str) return "—";
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

function SummaryCard({ label, value, sub }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 px-5 py-4">
      <p className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</p>
      <p className="mt-1 truncate text-2xl font-bold text-white" title={sub || undefined}>
        {value}
      </p>
      {sub && (
        <p className="mt-0.5 truncate text-xs text-slate-500" title={sub}>
          {sub}
        </p>
      )}
    </div>
  );
}

export default function GraphIntelligencePage() {
  const { api } = useAuth();
  const [providers, setProviders] = useState([]);
  const [providerId, setProviderId] = useState(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const [expandedArn, setExpandedArn] = useState(null);
  const [filterEscalated, setFilterEscalated] = useState(false);

  useEffect(() => {
    api
      .get("/api/v1/providers/")
      .then(({ data: body }) => {
        const list = Array.isArray(body) ? body : body?.results || [];
        setProviders(list);
        if (!providerId && list.length) setProviderId(list[0].id);
      })
      .catch(() => setProviders([]));
  }, [api]);

  const fetchData = useCallback(() => {
    if (!providerId) return;
    setLoading(true);
    setError(null);
    getGraphIntelligence(api, providerId)
      .then(setData)
      .catch((e) => setError(e?.response?.data?.detail || "Failed to load graph intelligence data."))
      .finally(() => setLoading(false));
  }, [api, providerId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleRun = () => {
    if (!providerId || running) return;
    setRunning(true);
    setError(null);
    runGraphAnalysis(api, providerId)
      .then(() => setTimeout(fetchData, 3000))
      .catch((e) => setError(e?.response?.data?.detail || "Failed to start graph analysis."))
      .finally(() => setRunning(false));
  };

  const summary = data?.summary || {};
  const highRiskNodes = data?.high_risk_nodes || [];
  const shadowRisks = data?.shadow_risks || [];
  const gdsOk = summary.gds_available === true;
  const hasScanData = Boolean(summary.last_run_timestamp);

  const visibleNodes = useMemo(() => {
    if (!filterEscalated) return highRiskNodes;
    return highRiskNodes.filter((n) => n.graph_adjusted_severity !== n.original_severity);
  }, [highRiskNodes, filterEscalated]);

  return (
    <div className="min-h-full bg-slate-950 p-6 text-white">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Graph Intelligence</h1>
          <p className="mt-1 text-sm text-slate-500">
            Graph-driven severity escalation and shadow risk detection
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"
            value={providerId ?? ""}
            onChange={(e) => setProviderId(Number(e.target.value) || null)}
          >
            {!providers.length && <option value="">No providers</option>}
            {providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name || p.aws_account_id || `Provider ${p.id}`}
              </option>
            ))}
          </select>
          <button
            onClick={handleRun}
            disabled={!providerId || running}
            className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50"
          >
            {running ? "Running…" : "Run Graph Analysis"}
          </button>
        </div>
      </div>

      {summary.last_run_timestamp && (
        <p className="mb-4 text-xs text-slate-500">
          Last deep scan: {new Date(summary.last_run_timestamp).toLocaleString()}
        </p>
      )}

      {error && (
        <div className="mb-4 rounded-xl border border-red-700/40 bg-red-900/20 px-4 py-3 text-sm text-red-300">
          {typeof error === "string" ? error : JSON.stringify(error)}
        </div>
      )}

      {!gdsOk && !loading && (
        <div className="mb-4 rounded-xl border border-yellow-700/40 bg-yellow-900/20 px-4 py-3 text-sm text-yellow-300">
          Neo4j Graph Data Science plugin is not available. Install GDS on Neo4j to enable this feature.
        </div>
      )}

      {data && (
        <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <SummaryCard label="High risk nodes" value={summary.total_high_risk_nodes ?? 0} />
          <SummaryCard label="Escalated" value={summary.total_escalated ?? 0} />
          <SummaryCard label="Shadow risks" value={summary.total_shadow_risks ?? 0} />
          <SummaryCard
            label="Most dangerous"
            value={truncate(summary.most_dangerous_node_arn || "—", 20)}
            sub={summary.most_dangerous_node_arn || undefined}
          />
        </div>
      )}

      {loading ? (
        <p className="py-16 text-center text-sm text-slate-500">Loading graph intelligence…</p>
      ) : (
        <>
          <section className="mb-8">
            <div className="mb-3 flex items-center justify-between gap-3">
              <h2 className="text-lg font-semibold">Escalated findings</h2>
              <label className="flex items-center gap-2 text-sm text-slate-400">
                <input
                  type="checkbox"
                  checked={filterEscalated}
                  onChange={(e) => setFilterEscalated(e.target.checked)}
                  className="rounded border-slate-600 bg-slate-800 accent-emerald-500"
                />
                Escalated only
              </label>
            </div>
            {visibleNodes.length === 0 ? (
              <p className="rounded-xl border border-slate-800 bg-slate-900 px-5 py-8 text-center text-sm text-slate-500">
                No graph-scored findings yet. Run a deep scan, then run graph analysis.
              </p>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-800">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900 text-left text-xs uppercase tracking-wider text-slate-500">
                      <th className="px-4 py-3">Resource</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Severity</th>
                      <th className="px-4 py-3">Reasons</th>
                      <th className="px-4 py-3">PageRank</th>
                      <th className="px-4 py-3">Hops</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 bg-slate-950">
                    {visibleNodes.map((node) => (
                      <Fragment key={node.arn}>
                        <tr
                          className="cursor-pointer hover:bg-slate-900/60"
                          onClick={() => setExpandedArn(expandedArn === node.arn ? null : node.arn)}
                        >
                          <td className="px-4 py-3 font-mono text-slate-300" title={node.arn}>
                            {truncate(node.arn)}
                          </td>
                          <td className="px-4 py-3 text-slate-400">{node.resource_type || "—"}</td>
                          <td className="px-4 py-3">
                            <span className={`rounded px-2 py-0.5 text-xs font-medium ${severityColors[node.original_severity] || severityColors.INFO}`}>
                              {node.original_severity}
                            </span>
                            {node.graph_adjusted_severity !== node.original_severity && (
                              <>
                                {" → "}
                                <span className={`rounded px-2 py-0.5 text-xs font-semibold ${severityColors[node.graph_adjusted_severity] || severityColors.INFO}`}>
                                  {node.graph_adjusted_severity}
                                </span>
                              </>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-1">
                              {(node.escalation_reasons || []).map((r) => (
                                <span key={r} className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
                                  {reasonLabels[r] || r}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-4 py-3 font-mono text-slate-300">
                            {(node.pagerank_score ?? 0).toFixed(4)}
                          </td>
                          <td className="px-4 py-3 font-mono">
                            {node.hops_from_internet >= 99 ? "∞" : node.hops_from_internet}
                          </td>
                        </tr>
                        {expandedArn === node.arn && (
                          <tr className="bg-slate-900/80">
                            <td colSpan={6} className="px-6 py-4 text-sm text-slate-300">
                              <p className="break-all font-mono">{node.arn}</p>
                              {node.rule_name && (
                                <p className="mt-2 text-slate-400">
                                  Rule: {node.rule_name} ({node.rule_id})
                                </p>
                              )}
                              <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                                <span>Betweenness: {(node.betweenness_score ?? 0).toFixed(1)}</span>
                                <span>Community: {node.community_size ?? 0}</span>
                                <span>K-core: {node.core_value ?? 0}</span>
                                <span>Bridge: {node.is_bridge ? "Yes" : "No"}</span>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section>
            <h2 className="mb-3 text-lg font-semibold">Shadow risks</h2>
            <p className="mb-3 text-sm text-slate-500">
              Resources with no active findings but similar misconfiguration patterns to flagged resources.
            </p>
            {shadowRisks.length === 0 ? (
              <p className="rounded-xl border border-slate-800 bg-slate-900 px-5 py-8 text-center text-sm text-slate-500">
                No shadow risks detected.
              </p>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-800">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900 text-left text-xs uppercase tracking-wider text-slate-500">
                      <th className="px-4 py-3">Resource</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Similarity</th>
                      <th className="px-4 py-3">Matched rule</th>
                      <th className="px-4 py-3">Matched resource</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 bg-slate-950">
                    {shadowRisks.map((risk) => {
                      const pct = Math.round((risk.violation_similarity_score || 0) * 100);
                      return (
                        <tr key={risk.arn} className="hover:bg-slate-900/60">
                          <td className="px-4 py-3 font-mono text-slate-300" title={risk.arn}>
                            {truncate(risk.arn)}
                          </td>
                          <td className="px-4 py-3 text-slate-400">{risk.resource_type || "—"}</td>
                          <td className="px-4 py-3 font-semibold text-orange-400">{pct}%</td>
                          <td className="px-4 py-3 font-mono text-slate-400">{risk.matched_rule_id || "—"}</td>
                          <td className="px-4 py-3 font-mono text-slate-400" title={risk.matched_resource_arn}>
                            {truncate(risk.matched_resource_arn, 35)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
