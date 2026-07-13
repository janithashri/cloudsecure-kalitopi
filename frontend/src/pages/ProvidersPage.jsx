import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function ProvidersPage() {
  const { api } = useAuth();
  const [providers, setProviders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [testingId, setTestingId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);

  useEffect(() => {
    api
      .get("/api/v1/providers/")
      .then(({ data }) => setProviders(Array.isArray(data) ? data : data?.results || []))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load providers"))
      .finally(() => setLoading(false));
  }, [api]);

  const testConnection = async (id) => {
    setTestingId(id);
    try {
      const { data } = await api.post(`/api/v1/providers/${id}/test-connection/`);
      setProviders((prev) =>
        prev.map((p) =>
          p.id === id ? { ...p, connection_verified: data.success, last_connection_test: new Date().toISOString() } : p
        )
      );
    } catch {
      setProviders((prev) =>
        prev.map((p) => (p.id === id ? { ...p, connection_verified: false } : p))
      );
    }
    setTestingId(null);
  };

  const deleteProvider = async (id) => {
    if (!confirm("Delete this provider?")) return;
    setDeletingId(id);
    try {
      await api.delete(`/api/v1/providers/${id}/`);
      setProviders((prev) => prev.filter((p) => p.id !== id));
    } catch {}
    setDeletingId(null);
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-900">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Providers</h1>
          <p className="mt-1 text-sm text-slate-400">Manage your connected cloud accounts</p>
        </div>
        <Link
          to="/connect"
          className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-400"
        >
          Connect New Account
        </Link>
      </div>

      {error && (
        <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {providers.length === 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-800/50 p-12 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/10">
            <svg className="h-8 w-8 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 15a4.5 4.5 0 004.5 4.5H18a3.75 3.75 0 001.332-7.257 3 3 0 00-3.758-3.848 5.25 5.25 0 00-10.233 2.33A4.502 4.502 0 002.25 15z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-white">No providers connected</h2>
          <p className="mt-2 text-slate-400">Connect your first AWS account to start scanning.</p>
          <Link
            to="/connect"
            className="mt-6 inline-block rounded-lg bg-emerald-500 px-6 py-3 font-medium text-white transition hover:bg-emerald-400"
          >
            Connect AWS Account
          </Link>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {providers.map((p) => (
            <div key={p.id} className="rounded-xl border border-slate-800 bg-slate-800/50 p-5 transition hover:border-emerald-500/30">
              <div className="mb-3 flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-orange-500/10 text-sm font-bold text-orange-400">
                    AWS
                  </div>
                  <div>
                    <h3 className="font-semibold text-white">{p.name || "Unnamed"}</h3>
                    <p className="font-mono text-xs text-slate-500">{p.aws_account_id}</p>
                  </div>
                </div>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                    p.connection_verified
                      ? "bg-emerald-500/10 text-emerald-400"
                      : "bg-red-500/10 text-red-400"
                  }`}
                >
                  {p.connection_verified ? "Connected" : "Unverified"}
                </span>
              </div>
              <div className="mb-4 text-xs text-slate-500">
                <p>Role: {p.inventory_role_name || "CloudSecureRole"}</p>
                {p.last_connection_test && (
                  <p>Tested: {new Date(p.last_connection_test).toLocaleString()}</p>
                )}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => testConnection(p.id)}
                  disabled={testingId === p.id}
                  className="flex-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 transition hover:bg-slate-700 disabled:opacity-50"
                >
                  {testingId === p.id ? "Testing..." : "Test Connection"}
                </button>
                <button
                  onClick={() => deleteProvider(p.id)}
                  disabled={deletingId === p.id}
                  className="rounded-lg border border-red-500/30 px-3 py-2 text-xs text-red-400 transition hover:bg-red-500/10 disabled:opacity-50"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
