import React, { useState } from "react";
import FindingsBadge from "./FindingsBadge";
import { suppressFinding } from "../api/findings";
import { useAuth } from "../context/AuthContext";

export default function RulesViolatedTable({
  findings = [],
  loading,
  onSuppress,
  filters = {},
  onFilterChange,
}) {
  const { api } = useAuth();
  const [expandedId, setExpandedId] = useState(null);
  const [suppressingId, setSuppressingId] = useState(null);

  const handleSuppress = async (id) => {
    setSuppressingId(id);
    try {
      await suppressFinding(api, id);
      onSuppress?.();
    } finally {
      setSuppressingId(null);
    }
  };

  if (loading) {
    return (
      <div className="rounded-lg border border-slate-200 bg-white p-8 text-center text-slate-500">
        Loading findings…
      </div>
    );
  }

  if (!findings.length) {
    return (
      <div className="rounded-lg border border-slate-200 bg-white p-8 text-center text-slate-500">
        No findings. Run a scan to check your AWS account.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-200">
          <thead className="bg-slate-50">
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
          <tbody className="divide-y divide-slate-200 bg-white">
            {findings.map((f) => (
              <React.Fragment key={f.id}>
                <tr
                  className="hover:bg-slate-50 cursor-pointer"
                  onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
                >
                  <td className="whitespace-nowrap px-4 py-3">
                    <FindingsBadge severity={f.severity} />
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-sm font-mono text-slate-700">{f.rule_id}</td>
                  <td className="max-w-xs truncate px-4 py-3 text-sm text-slate-700" title={f.rule_name}>
                    {f.rule_name}
                  </td>
                  <td className="max-w-xs truncate px-4 py-3 font-mono text-xs text-slate-600" title={f.arn}>
                    {f.arn.split("/").pop() || f.arn.slice(0, 32)}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-600">{f.resource_type}</td>
                  <td className="px-4 py-3 text-xs text-slate-600">
                    <span
                      title={
                        Array.isArray(f.compliance_frameworks)
                          ? f.compliance_frameworks.join(", ")
                          : ""
                      }
                    >
                      {Array.isArray(f.compliance_frameworks)
                        ? f.compliance_frameworks.join(", ")
                        : "—"}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                    {f.first_seen ? new Date(f.first_seen).toLocaleDateString() : "—"}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-right">
                    {f.status === "OPEN" && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleSuppress(f.id);
                        }}
                        disabled={suppressingId === f.id}
                        className="rounded bg-slate-200 px-2 py-1 text-xs hover:bg-slate-300 disabled:opacity-50"
                      >
                        {suppressingId === f.id ? "…" : "Suppress"}
                      </button>
                    )}
                  </td>
                </tr>
                {expandedId === f.id && (
                  <tr className="bg-slate-50">
                    <td colSpan={8} className="px-4 py-3 text-sm">
                      <p className="font-medium text-slate-700">Remediation</p>
                      <pre className="mt-1 whitespace-pre-wrap rounded bg-slate-200 p-3 font-mono text-xs text-slate-800">
                        {f.remediation_steps || "No steps provided."}
                      </pre>
                      <p className="mt-3 font-medium text-slate-700">Resource Config</p>
                      <pre className="mt-1 whitespace-pre-wrap rounded bg-slate-200 p-3 font-mono text-xs text-slate-800">
                        {f.resource_config
                          ? JSON.stringify(f.resource_config, null, 2)
                          : "No stored config found."}
                      </pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
