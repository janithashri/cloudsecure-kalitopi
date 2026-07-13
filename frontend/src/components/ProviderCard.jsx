import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";

function formatDate(d) {
  if (!d) return "—";
  try {
    return new Date(d).toLocaleString();
  } catch {
    return "—";
  }
}

export default function ProviderCard({ provider, onUpdate, onDelete }) {
  const { api } = useAuth();
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [testLoading, setTestLoading] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanMessage, setScanMessage] = useState(null);
  const [lastRun, setLastRun] = useState(null);
  const [runsPolling, setRunsPolling] = useState(false);

  const fetchRuns = () => {
    api.get(`/api/v1/providers/${provider.id}/inventory-runs/`).then(({ data }) => {
      if (data && data[0]) setLastRun(data[0]);
      else setLastRun(null);
    }).catch(() => setLastRun(null));
  };

  useEffect(() => {
    fetchRuns();
  }, [provider.id]);

  useEffect(() => {
    if (!runsPolling || !lastRun || lastRun.state !== "running") return;
    const t = setInterval(fetchRuns, 5000);
    return () => clearInterval(t);
  }, [runsPolling, lastRun?.state]);

  const handleRunScan = async () => {
    setScanMessage(null);
    setScanLoading(true);
    try {
      const { data } = await api.post(`/api/v1/providers/${provider.id}/inventory-pull/`);
      setScanMessage(data.status === "queued" ? "Scan started. Data will appear on the Dashboard when complete." : String(data.status));
      setRunsPolling(true);
      fetchRuns();
      // Worker creates the run asynchronously; refetch after a short delay so "Last scan" updates
      setTimeout(fetchRuns, 1500);
      setTimeout(fetchRuns, 4000);
    } catch (err) {
      setScanMessage(err.response?.data?.detail || err.message || "Scan failed");
    } finally {
      setScanLoading(false);
    }
  };

  const handleTest = async () => {
    setTestResult(null);
    setTestLoading(true);
    try {
      const { data } = await api.post(`/api/v1/providers/${provider.id}/test-connection/`);
      setTestResult({ success: true, ...data });
      onUpdate({
        connection_verified: true,
        last_connection_test: new Date().toISOString(),
      });
    } catch (err) {
      setTestResult({
        success: false,
        message: err.response?.data?.message || err.message || "Connection failed",
      });
      onUpdate({ connection_verified: false });
    } finally {
      setTestLoading(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.delete(`/api/v1/providers/${provider.id}/`);
      onDelete();
    } catch (_) {}
    setDeleting(false);
    setShowDeleteModal(false);
  };

  let statusBadge = "bg-slate-200 text-slate-700";
  if (provider.active && provider.connection_verified) statusBadge = "bg-green-100 text-green-800";
  else if (provider.active && !provider.connection_verified) statusBadge = "bg-amber-100 text-amber-800";

  const statusLabel =
    !provider.active ? "Inactive" : provider.connection_verified ? "Active" : "Unverified";

  return (
    <>
      <tr>
        <td className="px-4 py-3 text-slate-800">{provider.name}</td>
        <td className="px-4 py-3 font-mono text-slate-700">{provider.aws_account_id}</td>
        <td className="px-4 py-3">
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${statusBadge}`}>
            {statusLabel}
          </span>
        </td>
        <td className="px-4 py-3 text-slate-700">
          {provider.connection_verified ? "Yes" : "No"}
        </td>
        <td className="px-4 py-3 text-slate-600 text-sm">
          {lastRun ? (
            <span>
              <span className={lastRun.state === "running" ? "text-amber-600 font-medium" : lastRun.state === "failed" ? "text-red-600" : "text-slate-700"}>
                {lastRun.state === "running" ? "Running…" : lastRun.state}
              </span>
              {lastRun.stats && lastRun.stats.total !== undefined && (
                <span className="ml-1 text-slate-500">
                  (resources: {lastRun.stats.total}
                  {lastRun.stats.new != null || lastRun.stats.changed != null ? `, new: ${lastRun.stats.new ?? 0}, changed: ${lastRun.stats.changed ?? 0}` : ""})
                </span>
              )}
              <br />
              <span className="text-xs text-slate-400">{formatDate(lastRun.started_at)}</span>
            </span>
          ) : "—"}
        </td>
        <td className="px-4 py-3 text-slate-600 text-sm">
          {formatDate(provider.last_connection_test)}
        </td>
        <td className="px-4 py-3 text-right">
          <div className="flex flex-col items-end gap-1">
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={handleRunScan}
                disabled={scanLoading || !provider.connection_verified}
                className="rounded bg-green-600 px-3 py-1.5 text-sm text-white hover:bg-green-500 disabled:opacity-50"
                title={!provider.connection_verified ? "Verify connection first" : "Start inventory scan"}
              >
                {scanLoading ? "Starting…" : "Run scan"}
              </button>
              <button
                type="button"
                onClick={handleTest}
                disabled={testLoading}
                className="rounded bg-slate-600 px-3 py-1.5 text-sm text-white hover:bg-slate-500 disabled:opacity-50"
              >
                {testLoading ? "Testing..." : "Test Connection"}
              </button>
              <button
                type="button"
                onClick={() => setShowDeleteModal(true)}
                className="rounded bg-red-100 px-3 py-1.5 text-sm text-red-700 hover:bg-red-200"
              >
                Delete
              </button>
            </div>
            {testResult && (
              <span className={`text-xs ${testResult.success ? "text-green-600" : "text-red-600"}`}>
                {testResult.success ? "Connection verified" : testResult.message}
              </span>
            )}
            {scanMessage && (
              <span className="text-xs text-slate-600">{scanMessage}</span>
            )}
          </div>
        </td>
      </tr>
      {showDeleteModal && (
        <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/50">
          <div className="max-w-md rounded-lg bg-white p-6 shadow-xl">
            <p className="mb-4 text-slate-700">
              Delete provider &quot;{provider.name}&quot;? This cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowDeleteModal(false)}
                className="rounded bg-slate-200 px-3 py-1.5 text-slate-700 hover:bg-slate-300"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDelete}
                disabled={deleting}
                className="rounded bg-red-600 px-3 py-1.5 text-white hover:bg-red-500 disabled:opacity-50"
              >
                {deleting ? "Deleting..." : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
