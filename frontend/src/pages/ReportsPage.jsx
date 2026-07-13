import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext";
import { getFindings, getFindingsSummary } from "../api/findings";
import { generatePDFReport, generateCSVReport } from "../utils/reportExport";

export default function ReportsPage() {
  const { api } = useAuth();
  const [providers, setProviders] = useState([]);
  const [selectedProviderId, setSelectedProviderId] = useState(null);
  const [findings, setFindings] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(null);
  const [framework, setFramework] = useState("");

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

  const fetchData = useCallback(() => {
    if (!selectedProviderId) return;
    setLoading(true);
    const params = { status: "OPEN" };
    if (framework) params.framework = framework;

    Promise.allSettled([
      getFindings(api, selectedProviderId, params),
      getFindingsSummary(api, selectedProviderId),
    ]).then(([findRes, sumRes]) => {
      if (findRes.status === "fulfilled") {
        const list = findRes.value?.results ?? findRes.value?.data ?? (Array.isArray(findRes.value) ? findRes.value : []);
        setFindings(list);
      }
      if (sumRes.status === "fulfilled") setSummary(sumRes.value);
      setLoading(false);
    });
  }, [api, selectedProviderId, framework]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const providerName =
    providers.find((p) => p.id === selectedProviderId)?.name ||
    providers.find((p) => p.id === selectedProviderId)?.aws_account_id ||
    "Unknown";

  const handleExportPDF = async () => {
    setExporting("pdf");
    try {
      await generatePDFReport(findings, summary, providerName, framework);
    } catch (err) {
      console.error("PDF export failed:", err);
    }
    setExporting(null);
  };

  const handleExportCSV = () => {
    setExporting("csv");
    try {
      generateCSVReport(findings, providerName, framework);
    } catch (err) {
      console.error("CSV export failed:", err);
    }
    setExporting(null);
  };

  const totalFindings = findings.length;
  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const mediumCount = findings.filter((f) => f.severity === "MEDIUM").length;
  const lowCount = findings.filter((f) => f.severity === "LOW").length;

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Reports</h1>
        <p className="mt-1 text-sm text-slate-400">
          Generate and export compliance reports from your scan findings
        </p>
      </div>

      {/* Controls */}
      <div className="mb-6 flex flex-wrap items-center gap-4">
        <select
          value={selectedProviderId ?? ""}
          onChange={(e) => setSelectedProviderId(Number(e.target.value) || null)}
          className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2.5 text-sm text-white"
        >
          <option value="">Select provider</option>
          {providers.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name || p.aws_account_id}
            </option>
          ))}
        </select>

        <select
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2.5 text-sm text-white"
        >
          <option value="">All Frameworks</option>
          <option value="CIS">CIS AWS</option>
          <option value="DPDP">India DPDP</option>
          <option value="RBI">RBI</option>
          <option value="SBE">SBE</option>
        </select>

        <button
          onClick={handleExportPDF}
          disabled={!findings.length || exporting === "pdf"}
          className="flex items-center gap-2 rounded-lg bg-red-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-red-500 disabled:opacity-50"
        >
          {exporting === "pdf" ? (
            <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
          ) : (
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m.75 12l3 3m0 0l3-3m-3 3v-6m-1.5-9H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
          )}
          Export PDF
        </button>

        <button
          onClick={handleExportCSV}
          disabled={!findings.length || exporting === "csv"}
          className="flex items-center gap-2 rounded-lg bg-emerald-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:opacity-50"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
          </svg>
          Export CSV
        </button>
      </div>

      {/* Report preview */}
      <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-6">
        <div className="mb-6 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            Report Preview
            {framework && <span className="ml-2 text-sm text-emerald-400">({framework})</span>}
          </h2>
          <span className="text-sm text-slate-400">{new Date().toLocaleDateString()}</span>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
          </div>
        ) : (
          <>
            {/* Summary cards */}
            <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
              <div className="rounded-lg border border-slate-700 bg-slate-900 p-4 text-center">
                <p className="text-2xl font-bold text-white">{totalFindings}</p>
                <p className="text-xs text-slate-400">Total Findings</p>
              </div>
              <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-center">
                <p className="text-2xl font-bold text-red-400">{criticalCount}</p>
                <p className="text-xs text-slate-400">Critical</p>
              </div>
              <div className="rounded-lg border border-orange-500/30 bg-orange-500/5 p-4 text-center">
                <p className="text-2xl font-bold text-orange-400">{highCount}</p>
                <p className="text-xs text-slate-400">High</p>
              </div>
              <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-4 text-center">
                <p className="text-2xl font-bold text-yellow-400">{mediumCount + lowCount}</p>
                <p className="text-xs text-slate-400">Medium + Low</p>
              </div>
            </div>

            {/* Findings table preview */}
            {findings.length === 0 ? (
              <p className="py-8 text-center text-sm text-slate-500">
                No findings to export. Run a scan first.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-700">
                  <thead>
                    <tr>
                      <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Severity</th>
                      <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Rule</th>
                      <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Issue</th>
                      <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Resource</th>
                      <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Frameworks</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/50">
                    {findings.slice(0, 20).map((f) => (
                      <tr key={f.id}>
                        <td className="px-3 py-2.5">
                          <span
                            className={`rounded px-2 py-0.5 text-xs font-medium ${
                              f.severity === "CRITICAL"
                                ? "bg-red-500/10 text-red-400"
                                : f.severity === "HIGH"
                                  ? "bg-orange-500/10 text-orange-400"
                                  : f.severity === "MEDIUM"
                                    ? "bg-yellow-500/10 text-yellow-400"
                                    : "bg-blue-500/10 text-blue-400"
                            }`}
                          >
                            {f.severity}
                          </span>
                        </td>
                        <td className="max-w-[120px] truncate px-3 py-2.5 font-mono text-xs text-slate-400">
                          {f.rule_id}
                        </td>
                        <td className="max-w-[200px] truncate px-3 py-2.5 text-sm text-slate-300">
                          {f.rule_name}
                        </td>
                        <td className="max-w-[150px] truncate px-3 py-2.5 font-mono text-xs text-slate-500">
                          {f.arn?.split("/").pop() || f.arn?.slice(0, 30)}
                        </td>
                        <td className="px-3 py-2.5 text-xs text-slate-500">
                          {Array.isArray(f.compliance_frameworks)
                            ? f.compliance_frameworks.join(", ")
                            : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {findings.length > 20 && (
                  <p className="mt-3 text-center text-xs text-slate-500">
                    Showing 20 of {findings.length} findings. Export to see all.
                  </p>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
