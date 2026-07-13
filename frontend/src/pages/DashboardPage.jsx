import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getFindingsSummary, getFindings } from "../api/findings";
import { getInventoryRuns } from "../api/inventory";
import SeverityChart from "../components/charts/SeverityChart";
import ResourceTypeChart from "../components/charts/ResourceTypeChart";
import FrameworkChart from "../components/charts/FrameworkChart";

const severityColors = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
  LOW: "bg-blue-400",
  INFO: "bg-slate-400",
};

export default function DashboardPage() {
  const { api } = useAuth();
  const [providers, setProviders] = useState([]);
  const [selectedProviderId, setSelectedProviderId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [inventorySummary, setInventorySummary] = useState(null);
  const [latestRun, setLatestRun] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get("/api/v1/providers/")
      .then(({ data }) => {
        const list = Array.isArray(data) ? data : data?.results || [];
        setProviders(list);
        if (!selectedProviderId && list.length) setSelectedProviderId(list[0].id);
      })
      .catch(() => setProviders([]))
      .finally(() => setLoading(false));
  }, [api]);

  const fetchAll = useCallback(() => {
    if (!selectedProviderId) return;
    setLoading(true);

    Promise.allSettled([
      getFindingsSummary(api, selectedProviderId),
      getFindings(api, selectedProviderId, { status: "OPEN" }),
      api.get(`/api/v1/providers/${selectedProviderId}/inventory-summary/`).then((r) => r.data),
      getInventoryRuns(api, selectedProviderId),
    ]).then(([sumRes, findRes, invRes, runRes]) => {
      if (sumRes.status === "fulfilled") setSummary(sumRes.value);
      if (findRes.status === "fulfilled") {
        const list = findRes.value?.results ?? findRes.value?.data ?? (Array.isArray(findRes.value) ? findRes.value : []);
        setFindings(list);
      }
      if (invRes.status === "fulfilled") setInventorySummary(invRes.value);
      if (runRes.status === "fulfilled") {
        const runs = Array.isArray(runRes.value) ? runRes.value : runRes.value?.results || [];
        setLatestRun(runs[0] || null);
      }
      setLoading(false);
    });
  }, [api, selectedProviderId]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  const totalFindings = summary?.total_open ?? 0;
  const criticalHigh = (summary?.by_severity?.CRITICAL || 0) + (summary?.by_severity?.HIGH || 0);
  const totalResources = inventorySummary?.total_resources ?? 0;
  const frameworkCount = summary?.by_framework ? Object.keys(summary.by_framework).length : 0;

  const recentFindings = findings.slice(0, 5);

  if (loading && !summary) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      {/* Header */}
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-sm text-slate-400">
            {latestRun
              ? `Last scan: ${new Date(latestRun.started_at).toLocaleString()} (${latestRun.state})`
              : "No scans yet"}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {providers.length > 1 && (
            <select
              value={selectedProviderId ?? ""}
              onChange={(e) => setSelectedProviderId(Number(e.target.value) || null)}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
            >
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name || p.aws_account_id}
                </option>
              ))}
            </select>
          )}
          <button
            onClick={fetchAll}
            className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-sm text-slate-300 transition hover:bg-slate-700"
          >
            Refresh
          </button>
          <Link
            to="/scan"
            className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-400"
          >
            Run Scan
          </Link>
        </div>
      </div>

      {/* No providers state */}
      {!providers.length && (
        <div className="rounded-2xl border border-slate-800 bg-slate-800/50 p-12 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/10">
            <svg className="h-8 w-8 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 15a4.5 4.5 0 004.5 4.5H18a3.75 3.75 0 001.332-7.257 3 3 0 00-3.758-3.848 5.25 5.25 0 00-10.233 2.33A4.502 4.502 0 002.25 15z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-white">Connect Your Cloud Account</h2>
          <p className="mt-2 text-slate-400">Link an AWS account to start scanning for misconfigurations.</p>
          <Link
            to="/connect"
            className="mt-6 inline-block rounded-lg bg-emerald-500 px-6 py-3 font-medium text-white transition hover:bg-emerald-400"
          >
            Connect AWS Account
          </Link>
        </div>
      )}

      {/* Summary cards */}
      {providers.length > 0 && (
        <>
          <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
              <div className="flex items-center justify-between">
                <p className="text-sm text-slate-400">Total Findings</p>
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/10">
                  <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                  </svg>
                </div>
              </div>
              <p className="mt-3 text-3xl font-bold text-white">{totalFindings}</p>
              <p className="mt-1 text-xs text-slate-500">Open issues to address</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
              <div className="flex items-center justify-between">
                <p className="text-sm text-slate-400">Critical + High</p>
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-orange-500/10">
                  <svg className="h-5 w-5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15.362 5.214A8.252 8.252 0 0112 21 8.25 8.25 0 016.038 7.048 8.287 8.287 0 009 9.6a8.983 8.983 0 013.361-6.867 8.21 8.21 0 003 2.48z" />
                  </svg>
                </div>
              </div>
              <p className="mt-3 text-3xl font-bold text-orange-400">{criticalHigh}</p>
              <p className="mt-1 text-xs text-slate-500">Needs immediate attention</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
              <div className="flex items-center justify-between">
                <p className="text-sm text-slate-400">Resources Scanned</p>
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10">
                  <svg className="h-5 w-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375" />
                  </svg>
                </div>
              </div>
              <p className="mt-3 text-3xl font-bold text-white">{totalResources}</p>
              <p className="mt-1 text-xs text-slate-500">Across 7 AWS services</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
              <div className="flex items-center justify-between">
                <p className="text-sm text-slate-400">Frameworks</p>
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10">
                  <svg className="h-5 w-5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                  </svg>
                </div>
              </div>
              <p className="mt-3 text-3xl font-bold text-white">{frameworkCount}</p>
              <p className="mt-1 text-xs text-slate-500">CIS, DPDP, RBI, SBE</p>
            </div>
          </div>

          {/* Charts row */}
          <div className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
              <h3 className="mb-4 text-sm font-medium text-slate-300">Findings by Severity</h3>
              <SeverityChart data={summary?.by_severity} />
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
              <h3 className="mb-4 text-sm font-medium text-slate-300">Findings by Resource Type</h3>
              <ResourceTypeChart data={summary?.by_resource_type} />
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
              <h3 className="mb-4 text-sm font-medium text-slate-300">Compliance Frameworks</h3>
              <FrameworkChart data={summary?.by_framework} />
            </div>
          </div>

          {/* Bottom row: severity breakdown + recent findings */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Severity breakdown */}
            <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
              <h3 className="mb-4 text-sm font-medium text-slate-300">Severity Breakdown</h3>
              <div className="space-y-3">
                {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => {
                  const count = summary?.by_severity?.[sev] || 0;
                  const pct = totalFindings > 0 ? (count / totalFindings) * 100 : 0;
                  return (
                    <div key={sev} className="flex items-center gap-3">
                      <span className="w-20 text-xs font-medium text-slate-400">{sev}</span>
                      <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-700">
                        <div
                          className={`h-full rounded-full ${severityColors[sev]} transition-all`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="w-8 text-right text-xs font-medium text-slate-300">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Recent findings */}
            <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-sm font-medium text-slate-300">Recent Findings</h3>
                <Link to="/findings" className="text-xs text-emerald-400 hover:text-emerald-300">
                  View all
                </Link>
              </div>
              {recentFindings.length === 0 ? (
                <p className="py-8 text-center text-sm text-slate-500">
                  No findings yet. Run a scan to check your infrastructure.
                </p>
              ) : (
                <div className="space-y-2">
                  {recentFindings.map((f) => (
                    <div
                      key={f.id}
                      className="flex items-start gap-3 rounded-lg border border-slate-700/50 bg-slate-900/50 p-3"
                    >
                      <span
                        className={`mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full ${severityColors[f.severity] || "bg-slate-400"}`}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm text-slate-200">{f.rule_name}</p>
                        <p className="mt-0.5 truncate text-xs text-slate-500">
                          {f.resource_type} | {f.arn?.split("/").pop() || f.arn?.slice(0, 30)}
                        </p>
                      </div>
                      <span className="shrink-0 rounded bg-slate-700 px-2 py-0.5 text-xs text-slate-300">
                        {f.severity}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
