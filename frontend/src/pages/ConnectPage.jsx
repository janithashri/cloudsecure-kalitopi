import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function ConnectPage() {
  const { api } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [awsAccountId, setAwsAccountId] = useState("");
  const [inventoryRoleName, setInventoryRoleName] = useState("CloudSecureRole");
  const [providerId, setProviderId] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  const validAccountId = /^\d{12}$/.test(awsAccountId);

  const handleTestConnection = useCallback(async () => {
    setTestResult(null);
    setTesting(true);
    try {
      let id = providerId;
      if (!id) {
        const { data } = await api.post("/api/v1/providers/", {
          name: name || "Unnamed",
          aws_account_id: awsAccountId,
          inventory_role_name: inventoryRoleName,
        });
        id = data.id;
        setProviderId(id);
      } else {
        await api.patch(`/api/v1/providers/${id}/`, {
          name: name || "Unnamed",
          aws_account_id: awsAccountId,
          inventory_role_name: inventoryRoleName,
        });
      }
      const { data } = await api.post(`/api/v1/providers/${id}/test-connection/`);
      setTestResult({ success: true, ...data });
    } catch (err) {
      setTestResult({
        success: false,
        message: err.response?.data?.message || err.message || "Connection failed",
      });
    }
    setTesting(false);
  }, [api, providerId, name, awsAccountId, inventoryRoleName]);

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="mx-auto max-w-2xl">
        <h1 className="mb-2 text-2xl font-bold text-white">Connect AWS Account</h1>
        <p className="mb-6 text-sm text-slate-400">Link your AWS account using an IAM role for read-only access</p>

        <div className="space-y-5 rounded-xl border border-slate-800 bg-slate-800/50 p-6">
          <div>
            <label className="block text-sm font-medium text-slate-300">Provider Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-white placeholder-slate-500 outline-none focus:border-emerald-500"
              placeholder="My AWS Account"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300">AWS Account ID</label>
            <input
              type="text"
              value={awsAccountId}
              onChange={(e) => setAwsAccountId(e.target.value.replace(/\D/g, "").slice(0, 12))}
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 font-mono text-white placeholder-slate-500 outline-none focus:border-emerald-500"
              placeholder="123456789012"
              maxLength={12}
            />
            {awsAccountId && !validAccountId && (
              <p className="mt-1 text-xs text-amber-400">Must be exactly 12 digits</p>
            )}
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300">IAM Role Name</label>
            <input
              type="text"
              value={inventoryRoleName}
              onChange={(e) => setInventoryRoleName(e.target.value)}
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-white placeholder-slate-500 outline-none focus:border-emerald-500"
            />
          </div>

          <div className="flex gap-3">
            <button
              onClick={handleTestConnection}
              disabled={!validAccountId || testing}
              className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-400 disabled:opacity-50"
            >
              {testing ? "Testing..." : "Test Connection"}
            </button>
            {testResult?.success && (
              <button
                onClick={() => navigate("/providers")}
                className="rounded-lg border border-emerald-500 px-5 py-2.5 text-sm font-medium text-emerald-400 transition hover:bg-emerald-500/10"
              >
                Save & Go to Providers
              </button>
            )}
          </div>

          {testResult && (
            <div
              className={`rounded-lg border px-4 py-3 text-sm ${
                testResult.success
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                  : "border-red-500/30 bg-red-500/10 text-red-400"
              }`}
            >
              {testResult.success ? "Connection verified successfully!" : testResult.message}
            </div>
          )}
        </div>

        {/* IAM Setup Instructions */}
        <div className="mt-6 rounded-xl border border-slate-800 bg-slate-800/50 p-6">
          <h3 className="mb-3 text-sm font-semibold text-emerald-400">IAM Role Setup Guide</h3>
          <ol className="space-y-2 text-sm text-slate-400">
            <li>1. Go to AWS IAM Console and create a new role</li>
            <li>2. Select "Another AWS account" as the trusted entity</li>
            <li>3. Enter the CloudSecure account ID for cross-account access</li>
            <li>4. Attach the <code className="rounded bg-slate-700 px-1 py-0.5 text-xs text-emerald-400">ReadOnlyAccess</code> policy (or use the custom policy from README)</li>
            <li>5. Name the role <code className="rounded bg-slate-700 px-1 py-0.5 text-xs text-emerald-400">CloudSecureRole</code></li>
            <li>6. Enter your 12-digit AWS Account ID above and click Test Connection</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
