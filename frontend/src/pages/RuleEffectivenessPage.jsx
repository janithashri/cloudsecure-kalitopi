import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { getRuleEffectiveness } from "../api/ruleEffectiveness";

function SummaryCard({ label, value, sub, accent = "text-white" }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 px-5 py-4">
      <p className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${accent}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
    </div>
  );
}

function FunnelStep({ label, count, pct, active }) {
  return (
    <div className={`flex flex-1 flex-col items-center rounded-xl border px-4 py-5 ${active ? "border-emerald-500/40 bg-emerald-500/5" : "border-slate-800 bg-slate-900"}`}>
      <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
      <p className="mt-2 text-3xl font-bold text-white">{count}</p>
      {pct != null && <p className="mt-1 text-sm text-emerald-400">{pct}% reduction</p>}
    </div>
  );
}

export default function RuleEffectivenessPage() {
  const { api } = useAuth();
  const [providers, setProviders] = useState([]);
  const [providerId, setProviderId] = useState(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

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
    getRuleEffectiveness(api, providerId)
      .then(setData)
      .catch((e) => setError(e?.response?.data?.detail || "Failed to load rule effectiveness data."))
      .finally(() => setLoading(false));
  }, [api, providerId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const stage1 = data?.stage_1_consolidation;
  const stage2 = data?.stage_2_validation;
  const funnel = data?.combined_funnel;

  return (
    <div className="min-h-full bg-slate-950 p-8 text-slate-200">
      <div className="mx-auto max-w-6xl">
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white">Rule Effectiveness &amp; Alert Validation</h1>
            <p className="mt-1 max-w-2xl text-sm text-slate-400">
              Features 3 &amp; 4 — consolidated S3 rules (Paper A) plus active behavioral validation for
              policy-governed resources (Paper B).
            </p>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={providerId ?? ""}
              onChange={(e) => setProviderId(Number(e.target.value))}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
            >
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name || p.aws_account_id || `Provider ${p.id}`}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={fetchData}
              disabled={loading || !providerId}
              className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              {loading ? "Loading…" : "Refresh"}
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-6 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {!data && loading && (
          <p className="text-slate-500">Loading effectiveness metrics…</p>
        )}

        {data && (
          <>
            <section className="mb-10">
              <div className="mb-4 flex items-baseline justify-between gap-4">
                <h2 className="text-lg font-semibold text-white">Stage 1: Rule Consolidation</h2>
                <span className="text-xs text-slate-500">{stage1?.paper}</span>
              </div>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <SummaryCard
                  label="Fragmented rules"
                  value={`${stage1?.fragmented_rule_types ?? 0} → ${stage1?.consolidated_rule_types ?? 1}`}
                  sub="Distinct S3 public-access rule IDs"
                />
                <SummaryCard
                  label="Alerts before"
                  value={stage1?.old_alert_count ?? 0}
                  sub="Legacy CIS / DPDP / CERT-In S3 rules"
                />
                <SummaryCard
                  label="Alerts after"
                  value={stage1?.consolidated_alert_count ?? 0}
                  sub="CONSOLIDATED-S3-001"
                  accent="text-emerald-400"
                />
                <SummaryCard
                  label="Reduction"
                  value={`${stage1?.reduction_pct ?? 0}%`}
                  sub="Alert volume vs fragmented rules"
                  accent="text-emerald-400"
                />
              </div>
            </section>

            <section className="mb-10">
              <div className="mb-4 flex items-baseline justify-between gap-4">
                <h2 className="text-lg font-semibold text-white">Stage 2: Active Behavioral Validation</h2>
                <span className="text-xs text-slate-500">{stage2?.paper}</span>
              </div>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
                <SummaryCard label="S3 probes run" value={stage2?.s3_probes_run ?? 0} />
                <SummaryCard label="IAM key probes run" value={stage2?.iam_probes_run ?? 0} />
                <SummaryCard
                  label="Confirmed true positives"
                  value={stage2?.confirmed_true_positive ?? 0}
                  accent="text-orange-400"
                />
                <SummaryCard
                  label="Compensating controls"
                  value={stage2?.compensating_control_detected ?? 0}
                  accent="text-emerald-400"
                />
                <SummaryCard
                  label="Further reduction"
                  value={`${stage2?.additional_reduction_pct ?? 0}%`}
                  sub="After live exploitability probes"
                  accent="text-emerald-400"
                />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="mb-4 text-lg font-semibold text-white">Combined Funnel</h2>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-stretch">
                <FunnelStep label="Old rules" count={funnel?.old ?? 0} />
                <div className="hidden items-center text-slate-600 sm:flex">→</div>
                <FunnelStep
                  label="Consolidated"
                  count={funnel?.consolidated ?? 0}
                  pct={stage1?.reduction_pct}
                />
                <div className="hidden items-center text-slate-600 sm:flex">→</div>
                <FunnelStep
                  label="Validated (open)"
                  count={funnel?.validated ?? 0}
                  pct={stage2?.additional_reduction_pct}
                  active
                />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="mb-4 text-lg font-semibold text-white">
                Findings downgraded by validation
              </h2>
              {(data.downgraded_findings?.length ?? 0) === 0 ? (
                <p className="rounded-xl border border-slate-800 bg-slate-900 px-5 py-8 text-center text-sm text-slate-500">
                  No compensating-control downgrades yet. Run an inventory scan on S3 buckets — flagged
                  buckets with blocked anonymous access appear here (e.g. IP-restricted policies).
                </p>
              ) : (
                <div className="overflow-x-auto rounded-xl border border-slate-800">
                  <table className="min-w-full divide-y divide-slate-800 text-sm">
                    <thead className="bg-slate-900">
                      <tr>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">Resource</th>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">Rule</th>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">Condition</th>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">Probe</th>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">Compensating control</th>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">HTTP</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 bg-slate-950">
                      {data.downgraded_findings.map((row) => (
                        <tr key={`${row.arn}-${row.rule_id}`}>
                          <td className="px-4 py-3 font-mono text-xs text-slate-300">{row.resource_label}</td>
                          <td className="px-4 py-3 text-slate-300">{row.rule_id}</td>
                          <td className="px-4 py-3 text-slate-400">{row.matched_condition || "—"}</td>
                          <td className="px-4 py-3 text-slate-400">{row.probe_type || "—"}</td>
                          <td className="px-4 py-3 text-emerald-400">{row.compensating_control || "—"}</td>
                          <td className="px-4 py-3 text-slate-400">{row.http_status ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            {(data.confirmed_findings?.length ?? 0) > 0 && (
              <section>
                <h2 className="mb-4 text-lg font-semibold text-white">Confirmed exploitable (probe evidence)</h2>
                <div className="overflow-x-auto rounded-xl border border-slate-800">
                  <table className="min-w-full divide-y divide-slate-800 text-sm">
                    <thead className="bg-slate-900">
                      <tr>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">Resource</th>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">Probe</th>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">Classification</th>
                        <th className="px-4 py-3 text-left font-medium text-slate-400">HTTP</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 bg-slate-950">
                      {data.confirmed_findings.map((row) => (
                        <tr key={row.arn}>
                          <td className="px-4 py-3 font-mono text-xs text-slate-300">{row.resource_label}</td>
                          <td className="px-4 py-3 text-slate-400">{row.probe_type}</td>
                          <td className="px-4 py-3 text-orange-400">{row.classification}</td>
                          <td className="px-4 py-3 text-slate-400">{row.http_status ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
}
