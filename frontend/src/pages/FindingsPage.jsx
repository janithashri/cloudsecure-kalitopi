import { Fragment, useState, useEffect, useCallback, useMemo } from "react";
import { useAuth } from "../context/AuthContext";
import { getFindings, getFindingsSummary, suppressFinding } from "../api/findings";
import { triggerInventoryPull, getInventoryRuns } from "../api/inventory";
import { generatePDFReport, generateCSVReport } from "../utils/reportExport";
import { createCustomRule, getCustomRules } from "../api/customRules";
import SeverityChart from "../components/charts/SeverityChart";

const severityColors = {
  CRITICAL: "bg-red-500/10 text-red-400",
  HIGH: "bg-orange-500/10 text-orange-400",
  MEDIUM: "bg-yellow-500/10 text-yellow-400",
  LOW: "bg-blue-500/10 text-blue-400",
  INFO: "bg-slate-500/10 text-slate-400",
};

const KNOWN_RESOURCE_TYPES = [
  "AWS::S3::Bucket",
  "AWS::EC2::SecurityGroup",
  "AWS::EC2::Instance",
  "AWS::IAM::User",
  "AWS::IAM::Role",
  "AWS::RDS::DBInstance",
  "AWS::KMS::Key",
  "AWS::CloudTrail::Trail",
];

function formatResourceType(value) {
  return value.replace(/^AWS::/, "").replace(/::/g, " ");
}

export default function FindingsPage() {
  const { api } = useAuth();
  const [providers, setProviders] = useState([]);
  const [selectedProviderId, setSelectedProviderId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [filters, setFilters] = useState({ status: "OPEN", framework: "", resource_type: "" });
  const [expandedId, setExpandedId] = useState(null);
  const [suppressingId, setSuppressingId] = useState(null);
  const [toast, setToast] = useState(null);
  const [customRules, setCustomRules] = useState([]);
  const [savingCustomRule, setSavingCustomRule] = useState(false);
  const [customRuleForm, setCustomRuleForm] = useState({
    name: "",
    resource_type: "AWS::S3::Bucket",
    rule_id: "",
    severity: "MEDIUM",
    compliance_frameworks: "",
    description: "",
    rego_policy: "",
  });

  useEffect(() => {
    api
      .get("/api/v1/providers/")
      .then(({ data }) => {
        const list = Array.isArray(data) ? data : data?.results || [];
        setProviders(list);
        if (!selectedProviderId && list.length) setSelectedProviderId(list[0].id);
      })
      .catch(() => setProviders([]));
  }, [api]);

  const fetchSummary = useCallback(() => {
    if (!selectedProviderId) return;
    setLoadingSummary(true);
    getFindingsSummary(api, selectedProviderId)
      .then(setSummary)
      .catch(() => setSummary(null))
      .finally(() => setLoadingSummary(false));
  }, [api, selectedProviderId]);

  const fetchFindings = useCallback(() => {
    if (!selectedProviderId) return;
    setLoadingFindings(true);
    getFindings(api, selectedProviderId, filters)
      .then((data) => {
        const list = data?.results ?? data?.data ?? (Array.isArray(data) ? data : []);
        setFindings(list);
      })
      .catch(() => setFindings([]))
      .finally(() => setLoadingFindings(false));
  }, [api, selectedProviderId, filters]);

  const fetchCustomRules = useCallback(() => {
    getCustomRules(api, selectedProviderId)
      .then((list) => setCustomRules(Array.isArray(list) ? list : []))
      .catch(() => setCustomRules([]));
  }, [api, selectedProviderId]);

  useEffect(() => { fetchSummary(); }, [fetchSummary]);
  useEffect(() => { fetchFindings(); }, [fetchFindings]);
  useEffect(() => { fetchCustomRules(); }, [fetchCustomRules]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 5000);
    return () => clearTimeout(t);
  }, [toast]);

  const handleSuppress = async (id) => {
    setSuppressingId(id);
    try {
      await suppressFinding(api, id);
      fetchFindings();
      fetchSummary();
      setToast({ type: "success", message: "Finding suppressed" });
    } finally {
      setSuppressingId(null);
    }
  };

  const providerName =
    providers.find((p) => p.id === selectedProviderId)?.name ||
    providers.find((p) => p.id === selectedProviderId)?.aws_account_id ||
    "Unknown";

  const totalOpen = summary?.total_open ?? 0;
  const criticalHigh = (summary?.by_severity?.CRITICAL || 0) + (summary?.by_severity?.HIGH || 0);

  const resourceTypeOptions = useMemo(() => {
    const fromSummary = Object.keys(summary?.by_resource_type || {});
    const fromFindings = findings.map((f) => f.resource_type).filter(Boolean);
    return [...new Set([...KNOWN_RESOURCE_TYPES, ...fromSummary, ...fromFindings])].sort();
  }, [summary, findings]);
  const handleCreateCustomRule = async (e) => {
    e.preventDefault();
    setSavingCustomRule(true);
    try {
      const frameworks = customRuleForm.compliance_frameworks
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
      await createCustomRule(api, {
        ...customRuleForm,
        provider: selectedProviderId || null,
        compliance_frameworks: frameworks,
      });
      setCustomRuleForm({
        name: "",
        resource_type: customRuleForm.resource_type,
        rule_id: "",
        severity: "MEDIUM",
        compliance_frameworks: "",
        description: "",
        rego_policy: "",
      });
      setToast({ type: "success", message: "Custom rule created" });
      fetchCustomRules();
    } catch {
      setToast({ type: "error", message: "Failed to create custom rule" });
    } finally {
      setSavingCustomRule(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Findings</h1>
          <p className="mt-1 text-sm text-slate-400">
            {totalOpen} open findings | {criticalHigh} critical+high
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => generatePDFReport(findings, summary, providerName, filters.framework)}
            disabled={!findings.length}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 transition hover:bg-slate-700 disabled:opacity-50"
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m.75 12l3 3m0 0l3-3m-3 3v-6m-1.5-9H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            PDF
          </button>
          <button
            onClick={() => generateCSVReport(findings, providerName, filters.framework)}
            disabled={!findings.length}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 transition hover:bg-slate-700 disabled:opacity-50"
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            CSV
          </button>
        </div>
      </div>

      {toast && (
        <div
          className={`mb-4 rounded-xl border px-4 py-3 text-sm ${
            toast.type === "success"
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
              : "border-red-500/30 bg-red-500/10 text-red-400"
          }`}
        >
          {toast.message}
        </div>
      )}

      {/* Filters */}
      <div className="mb-6 rounded-xl border border-slate-800 bg-slate-800/40 p-4">
        <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Filters</p>
        <div className="flex flex-wrap items-center gap-3">
        <select
          value={selectedProviderId ?? ""}
          onChange={(e) => setSelectedProviderId(Number(e.target.value) || null)}
          className="min-w-[160px] rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
          aria-label="Provider"
        >
          <option value="">Select provider</option>
          {providers.map((p) => (
            <option key={p.id} value={p.id}>{p.name || p.aws_account_id}</option>
          ))}
        </select>
        <select
          value={filters.status || ""}
          onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value || undefined }))}
          className="min-w-[120px] rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
          aria-label="Status"
        >
          <option value="OPEN">Open</option>
          <option value="SUPPRESSED">Suppressed</option>
          <option value="RESOLVED">Resolved</option>
          <option value="COMPENSATING_CONTROL_DETECTED">Compensating control</option>
          <option value="">All statuses</option>
        </select>
        <select
          value={filters.severity || ""}
          onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value || undefined }))}
          className="min-w-[140px] rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
          aria-label="Severity"
        >
          <option value="">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select
          value={filters.resource_type || ""}
          onChange={(e) => setFilters((f) => ({ ...f, resource_type: e.target.value }))}
          className="min-w-[180px] rounded-lg border border-emerald-700/50 bg-slate-800 px-3 py-2 text-sm text-white"
          aria-label="Resource type"
        >
          <option value="">All resource types</option>
          {resourceTypeOptions.map((rt) => (
            <option key={rt} value={rt}>
              {formatResourceType(rt)}
            </option>
          ))}
        </select>
        <select
          value={filters.framework || ""}
          onChange={(e) => setFilters((f) => ({ ...f, framework: e.target.value }))}
          className="min-w-[140px] rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
          aria-label="Framework"
        >
          <option value="">All frameworks</option>
          <option value="CIS">CIS</option>
          <option value="DPDP">DPDP</option>
          <option value="RBI">RBI</option>
          <option value="SBE">SBE</option>
        </select>
        <button
          onClick={() => { fetchSummary(); fetchFindings(); }}
          className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-sm text-slate-300 transition hover:bg-slate-700"
        >
          Refresh
        </button>
        </div>
      </div>

      {/* Summary + chart */}
      <div className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="col-span-2 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-4">
            <p className="text-xs text-slate-400">Total Open</p>
            <p className="mt-1 text-2xl font-bold text-white">{totalOpen}</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-4">
            <p className="text-xs text-slate-400">Critical+High</p>
            <p className="mt-1 text-2xl font-bold text-orange-400">{criticalHigh}</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-4">
            <p className="text-xs text-slate-400">Frameworks</p>
            <p className="mt-1 text-2xl font-bold text-white">
              {summary?.by_framework ? Object.keys(summary.by_framework).length : 0}
            </p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-4">
            <p className="text-xs text-slate-400">New This Scan</p>
            <p className="mt-1 text-2xl font-bold text-cyan-400">{summary?.new_this_run ?? 0}</p>
          </div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-4">
          <SeverityChart data={summary?.by_severity} />
        </div>
      </div>

      {/* Findings table */}
      <div className="mb-6 rounded-xl border border-slate-800 bg-slate-800/50 p-4">
        <h2 className="text-sm font-semibold text-white">Custom Rules</h2>
        <p className="mt-1 text-xs text-slate-400">
          Create tenant rules with your own Rego policy. These are stored and ready for engine integration.
        </p>
        <form className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2" onSubmit={handleCreateCustomRule}>
          <input
            value={customRuleForm.name}
            onChange={(e) => setCustomRuleForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="Rule name"
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
            required
          />
          <input
            value={customRuleForm.rule_id}
            onChange={(e) => setCustomRuleForm((f) => ({ ...f, rule_id: e.target.value }))}
            placeholder="Rule ID (e.g. CUSTOM-S3-001)"
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
            required
          />
          <select
            value={customRuleForm.resource_type}
            onChange={(e) => setCustomRuleForm((f) => ({ ...f, resource_type: e.target.value }))}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
          >
            <option value="AWS::S3::Bucket">AWS::S3::Bucket</option>
            <option value="AWS::EC2::SecurityGroup">AWS::EC2::SecurityGroup</option>
            <option value="AWS::EC2::Instance">AWS::EC2::Instance</option>
            <option value="AWS::IAM::User">AWS::IAM::User</option>
            <option value="AWS::IAM::Role">AWS::IAM::Role</option>
            <option value="AWS::RDS::DBInstance">AWS::RDS::DBInstance</option>
            <option value="AWS::KMS::Key">AWS::KMS::Key</option>
            <option value="AWS::CloudTrail::Trail">AWS::CloudTrail::Trail</option>
          </select>
          <select
            value={customRuleForm.severity}
            onChange={(e) => setCustomRuleForm((f) => ({ ...f, severity: e.target.value }))}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
          >
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
          <input
            value={customRuleForm.compliance_frameworks}
            onChange={(e) => setCustomRuleForm((f) => ({ ...f, compliance_frameworks: e.target.value }))}
            placeholder="Frameworks CSV (CIS,DPDP,RBI,SBE)"
            className="md:col-span-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
          />
          <input
            value={customRuleForm.description}
            onChange={(e) => setCustomRuleForm((f) => ({ ...f, description: e.target.value }))}
            placeholder="Description"
            className="md:col-span-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
          />
          <textarea
            value={customRuleForm.rego_policy}
            onChange={(e) => setCustomRuleForm((f) => ({ ...f, rego_policy: e.target.value }))}
            placeholder="Paste Rego policy"
            className="md:col-span-2 min-h-[120px] rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-xs text-white"
            required
          />
          <div className="md:col-span-2 flex justify-end">
            <button
              type="submit"
              disabled={savingCustomRule}
              className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              {savingCustomRule ? "Saving..." : "Create Rule"}
            </button>
          </div>
        </form>
        <div className="mt-4">
          <p className="mb-2 text-xs text-slate-400">Saved rules ({customRules.length})</p>
          <div className="max-h-40 overflow-y-auto rounded-lg border border-slate-700">
            {customRules.length === 0 ? (
              <div className="px-3 py-2 text-xs text-slate-500">No custom rules yet.</div>
            ) : (
              customRules.map((r) => (
                <div key={r.id} className="flex items-center justify-between border-b border-slate-800 px-3 py-2 text-xs last:border-b-0">
                  <span className="text-slate-300">{r.rule_id} - {r.name}</span>
                  <span className="text-slate-500">{r.resource_type}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-800/50 overflow-hidden">
        {loadingFindings ? (
          <div className="flex items-center justify-center py-12">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
          </div>
        ) : findings.length === 0 ? (
          <div className="py-12 text-center text-sm text-slate-500">
            No findings. Run a scan to check your AWS account.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-700">
              <thead className="bg-slate-800/80">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-500">Severity</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-500">Rule ID</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-500">Issue</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-500">Resource</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-500">Type</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-500">Frameworks</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-500">First Seen</th>
                  <th className="px-4 py-3 text-right text-xs font-medium uppercase text-slate-500">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {findings.map((f) => (
                  <Fragment key={f.id}>
                    <tr
                      className="cursor-pointer transition hover:bg-slate-800/50"
                      onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
                    >
                      <td className="whitespace-nowrap px-4 py-3">
                        <span className={`rounded px-2 py-0.5 text-xs font-medium ${severityColors[f.severity] || severityColors.INFO}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-400">{f.rule_id}</td>
                      <td className="max-w-[200px] truncate px-4 py-3 text-sm text-slate-300" title={f.rule_name}>{f.rule_name}</td>
                      <td className="max-w-[150px] truncate px-4 py-3 font-mono text-xs text-slate-500" title={f.arn}>
                        {f.arn?.split("/").pop() || f.arn?.slice(0, 30)}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">{f.resource_type}</td>
                      <td className="px-4 py-3 text-xs text-slate-500">
                        {Array.isArray(f.compliance_frameworks) ? f.compliance_frameworks.join(", ") : ""}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                        {f.first_seen ? new Date(f.first_seen).toLocaleDateString() : ""}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-right">
                        {f.status === "OPEN" && (
                          <button
                            onClick={(e) => { e.stopPropagation(); handleSuppress(f.id); }}
                            disabled={suppressingId === f.id}
                            className="rounded bg-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-600 disabled:opacity-50"
                          >
                            {suppressingId === f.id ? "..." : "Suppress"}
                          </button>
                        )}
                      </td>
                    </tr>
                    {expandedId === f.id && (
                      <tr className="bg-slate-800/30">
                        <td colSpan={8} className="px-4 py-4">
                          <div className="space-y-3">
                            <div>
                              <p className="text-xs font-medium text-emerald-400">Remediation</p>
                              <pre className="mt-1 whitespace-pre-wrap rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-300">
                                {f.remediation_steps || "No steps provided."}
                              </pre>
                            </div>
                            <div>
                              <p className="text-xs font-medium text-emerald-400">Resource Config</p>
                              <pre className="mt-1 max-h-48 overflow-y-auto whitespace-pre-wrap rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-300">
                                {f.resource_config ? JSON.stringify(f.resource_config, null, 2) : "No stored config found."}
                              </pre>
                            </div>
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
      </div>
    </div>
  );
}
