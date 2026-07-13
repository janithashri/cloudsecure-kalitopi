import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext";
import { triggerInventoryPull, getInventoryRuns } from "../api/inventory";

const serviceInfo = [
  { type: "S3", name: "Amazon S3", desc: "Scan buckets for public access, encryption, versioning, and logging misconfigurations", icon: "S3" },
  { type: "EC2", name: "Amazon EC2", desc: "Check instances and security groups for open ports and network exposure", icon: "EC2" },
  { type: "IAM", name: "AWS IAM", desc: "Audit users, roles, policies, and MFA configuration", icon: "IAM" },
  { type: "RDS", name: "Amazon RDS", desc: "Verify database encryption, public access, and backup settings", icon: "RDS" },
  { type: "KMS", name: "AWS KMS", desc: "Check key rotation, policies, and encryption key management", icon: "KMS" },
  { type: "CloudTrail", name: "AWS CloudTrail", desc: "Ensure logging is enabled with proper event selectors", icon: "CT" },
];

export default function ScanPage() {
  const { api } = useAuth();
  const [providers, setProviders] = useState([]);
  const [selectedProviderId, setSelectedProviderId] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanPolling, setScanPolling] = useState(false);
  const [latestRun, setLatestRun] = useState(null);
  const [scanStartedAt, setScanStartedAt] = useState(null);
  const [toast, setToast] = useState(null);
  const [runs, setRuns] = useState([]);

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

  const fetchRuns = useCallback(() => {
    if (!selectedProviderId) return;
    return getInventoryRuns(api, selectedProviderId)
      .then((data) => {
        const list = Array.isArray(data) ? data : data?.results || [];
        setRuns(list);
        setLatestRun(list[0] || null);
      })
      .catch(() => {});
  }, [api, selectedProviderId]);

  useEffect(() => {
    fetchRuns();
  }, [fetchRuns]);

  const runScan = useCallback(async () => {
    if (!selectedProviderId) return;
    setScanLoading(true);
    setScanPolling(true);
    setScanStartedAt(new Date().toISOString());
    try {
      await triggerInventoryPull(api, selectedProviderId);
      await fetchRuns();
      setTimeout(fetchRuns, 1500);
    } catch {
      setScanPolling(false);
      setToast({ type: "error", message: "Scan failed - check backend logs" });
    } finally {
      setScanLoading(false);
    }
  }, [api, selectedProviderId, fetchRuns]);

  useEffect(() => {
    if (!scanPolling) return;
    const t = setInterval(fetchRuns, 5000);
    return () => clearInterval(t);
  }, [scanPolling, fetchRuns]);

  useEffect(() => {
    if (!scanPolling || !latestRun) return;
    if (scanStartedAt && latestRun.started_at && latestRun.started_at < scanStartedAt) return;
    if (latestRun.state === "running") return;
    setScanPolling(false);
    if (latestRun.state === "completed" || latestRun.state === "partial") {
      setToast({ type: "success", message: "Scan complete! Check Findings for results." });
    } else {
      setToast({ type: "error", message: "Scan failed - check logs" });
    }
  }, [scanPolling, latestRun, scanStartedAt]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 6000);
    return () => clearTimeout(t);
  }, [toast]);

  const isScanning = scanLoading || scanPolling;

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Scan</h1>
        <p className="mt-1 text-sm text-slate-400">
          One-click security scan across all supported AWS services
        </p>
      </div>

      {toast && (
        <div
          className={`mb-6 rounded-xl border px-4 py-3 text-sm ${
            toast.type === "success"
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
              : "border-red-500/30 bg-red-500/10 text-red-400"
          }`}
        >
          {toast.message}
        </div>
      )}

      {/* Provider select + scan button */}
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

        <button
          onClick={runScan}
          disabled={!selectedProviderId || isScanning}
          className="flex items-center gap-2 rounded-lg bg-emerald-500 px-6 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-400 disabled:opacity-50"
        >
          {isScanning ? (
            <>
              <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
              Scanning...
            </>
          ) : (
            <>
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
              </svg>
              Scan Now
            </>
          )}
        </button>
      </div>

      {/* Service cards grid */}
      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {serviceInfo.map((svc) => (
          <div
            key={svc.type}
            className="rounded-xl border border-slate-800 bg-slate-800/50 p-5 transition hover:border-emerald-500/30"
          >
            <div className="mb-3 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10 text-xs font-bold text-emerald-400">
                {svc.icon}
              </div>
              <h3 className="font-semibold text-white">{svc.name}</h3>
            </div>
            <p className="text-sm text-slate-400">{svc.desc}</p>
            <div className="mt-3 flex items-center gap-2">
              <span className="rounded bg-slate-700 px-2 py-0.5 text-xs text-slate-300">AWS</span>
              <span className="rounded bg-slate-700 px-2 py-0.5 text-xs text-slate-300">CIS</span>
            </div>
          </div>
        ))}
      </div>

      {/* Scan history */}
      <div className="rounded-xl border border-slate-800 bg-slate-800/50 p-5">
        <h3 className="mb-4 text-sm font-medium text-slate-300">Scan History</h3>
        {runs.length === 0 ? (
          <p className="py-4 text-center text-sm text-slate-500">No scans yet</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-700">
              <thead>
                <tr>
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Status</th>
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Started</th>
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Finished</th>
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Delta</th>
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Config Signals</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {runs.slice(0, 10).map((run, i) => (
                  <tr key={run.id || i}>
                    <td className="px-3 py-2.5">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${
                          run.state === "completed"
                            ? "bg-emerald-500/10 text-emerald-400"
                            : run.state === "running"
                              ? "bg-blue-500/10 text-blue-400"
                              : run.state === "partial"
                                ? "bg-yellow-500/10 text-yellow-400"
                                : "bg-red-500/10 text-red-400"
                        }`}
                      >
                        {run.state === "running" && (
                          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-blue-400" />
                        )}
                        {run.state}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-xs text-slate-400">
                      {run.started_at ? new Date(run.started_at).toLocaleString() : "—"}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-slate-400">
                      {run.completed_at ? new Date(run.completed_at).toLocaleString() : "—"}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-slate-400">
                      {run.stats?.delta_count ?? 0}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-slate-400">
                      {run.stats?.config_changed_signals ?? 0}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
