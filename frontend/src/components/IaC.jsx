import React, { useState } from "react";
import {
  GlobeAltIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  ExclamationCircleIcon,
  InformationCircleIcon,
  ShieldCheckIcon,
  ArrowDownTrayIcon,
  SparklesIcon
} from "@heroicons/react/24/outline";
 

const VulnerabilityCard = ({ issue }) => {
  const severity = issue.severity.toUpperCase();

  const severityMap = {
    CRITICAL: {
      color: "red",
      icon: <ExclamationTriangleIcon className="w-5 h-5" />,
    },
    HIGH: {
      color: "red",
      icon: <ExclamationTriangleIcon className="w-5 h-5" />,
    },
    MEDIUM: {
      color: "yellow",
      icon: <ExclamationCircleIcon className="w-5 h-5" />,
    },
    LOW: { color: "blue", icon: <InformationCircleIcon className="w-5 h-5" /> },
  };

  const { color, icon } = severityMap[severity] || severityMap["LOW"];

  const location = issue.location;
  const simplifiedLocation = `${location.filename}:${location.start_line}`;

  return (
    <div className="bg-slate-900 border border-slate-700 p-6 rounded-xl space-y-4 hover:border-slate-600 transition-colors">
      <div className="flex items-center justify-between gap-4">
        <h4 className="text-lg font-bold text-white leading-tight">
          {issue.rule_description}
        </h4>
        <div
          className={`flex items-center gap-2 px-3 py-1 rounded-full border border-${color}-500/30 bg-${color}-500/10 text-${color}-400 text-sm font-semibold whitespace-nowrap`}
        >
          {icon}
          {severity}
        </div>
      </div>

      <p className="text-slate-400 text-sm leading-relaxed">
        {issue.description}
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-slate-800 text-sm">
        <div>
          <span className="text-slate-500 block">Resolution:</span>
          <span className="text-white">{issue.resolution}</span>
        </div>
      </div>

      {issue.ai_fix && (
        <div className="mt-4 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
          <div className="flex items-center gap-2 mb-2 text-emerald-400 font-bold">
            <SparklesIcon className="w-4 h-4" />
            AI Suggested Remediation
          </div>
          <div className="text-slate-300 text-sm whitespace-pre-line font-mono">
            {issue.ai_fix}
          </div>
        </div>
      )}
    </div>
  );
};

const IacScanner = () => {
  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [scanPerformed, setScanPerformed] = useState(false);
  const [error, setError] = useState("");
  const [scanId, setScanId] = useState(null); 

  const triggerScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResults([]);
    setError("");
    setScanPerformed(false); 


    if (!githubUrl.includes("github.com")) {
      setError("Please enter a valid GitHub repository URL.");
      setLoading(false);
      return;
    }

    try {
      const response = await fetch("http://localhost:5000/api/iac/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: githubUrl }),
      });

      const data = await response.json();
      if (!response.ok || data.error) {
        throw new Error(data.error || "Failed to complete scan.");
      }


      console.log("Scan response:", data);
      setScanId(data.scanId);
      setResults(data.results || []);
    } catch (err) {
      setError(
        err.message ||
          "Backend connection failed. Check if your Flask server is running.",
      );
    } finally {
      setLoading(false);
      setScanPerformed(true);
    }
  };

  const downloadReport = async (format) => {
    try {
     
      const response = await fetch(
        `http://localhost:5000/api/iac/export?format=${format}&scanId=${scanId}`,
      );

      if (!response.ok) throw new Error("Server could not generate the PDF.");

      
      const blob = await response.blob();

      // 3. Create a temporary local URL for that Blob
      const url = window.URL.createObjectURL(blob);

      // 4. Create a hidden <a> tag, click it, and then remove it
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `CloudSecure_Audit.${format}`); // File name in user's browser
      document.body.appendChild(link);
      link.click();

      // 5. Cleanup
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError("Download failed: " + err.message);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-white font-sans">
      <div className="max-w-5xl mx-auto py-24 px-6 relative">
        {/* Background Gradients */}
        <div className="absolute inset-0 bg-gradient-to-br from-emerald-900/20 via-transparent to-cyan-900/20 opacity-40" />
        <div className="absolute inset-0">
          <div className="absolute left-1/4 top-1/4 h-64 w-64 rounded-full bg-emerald-500/5 blur-3xl" />
          <div className="absolute bottom-1/4 right-1/4 h-64 w-64 rounded-full bg-cyan-500/5 blur-3xl" />
        </div>

        {/* Content with relative positioning to be on top of gradients */}
        <div className="relative">
          {/* Header Section */}
          <div className="mb-12 text-center">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-1.5 text-sm text-emerald-400">
              <GlobeAltIcon className="h-4 w-4" />
              Scan Repository
            </div>
            <h1 className="text-4xl font-bold leading-tight tracking-tight sm:text-5xl lg:text-6xl mb-4">
              Secure your Infrastructure{" "}
              <span className="text-emerald-400">(IaC)</span>
            </h1>
            <p className="max-w-2xl mx-auto mt-6 text-lg leading-relaxed text-slate-400">
              Enter a public GitHub repository URL to audit Terraform files
              against security benchmarks for comprehensive cloud security.
            </p>
          </div>

          {/* Input Form Section */}
          <form
            onSubmit={triggerScan}
            className="bg-slate-900 p-8 rounded-xl shadow-2xl border border-slate-700"
          >
            <div className="flex flex-col gap-6">
              <label className="text-sm font-semibold tracking-wider uppercase text-slate-300">
                GitHub Repository URL
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                  <GlobeAltIcon className="h-6 w-6 text-slate-500" />
                </div>
                <input
                  type="text"
                  placeholder="https://github.com/username/project"
                  className="block w-full pl-12 pr-4 py-4 bg-slate-800/50 border border-slate-700 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-transparent outline-none transition text-white text-lg font-mono placeholder-slate-600"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  disabled={loading}
                  required
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className={`w-full py-4 px-6 rounded-lg font-semibold text-lg flex items-center justify-center gap-3 transition ${
                  loading
                    ? "bg-slate-700 cursor-not-allowed text-slate-500"
                    : "bg-emerald-500 text-white hover:bg-emerald-400 shadow-lg shadow-emerald-500/25"
                }`}
              >
                {loading ? (
                  <>
                    <ArrowPathIcon className="h-6 w-6 animate-spin" />
                    Auditing Repository...
                  </>
                ) : (
                  "Launch IaC Scanner"
                )}
              </button>
            </div>
          </form>

          {/* --- RESULTS SECTION --- */}
          <div className="mt-16 space-y-12 relative">
            {/* 1. Loading State Skeleton */}
            {loading && (
              <div className="animate-pulse space-y-6">
                <div className="h-5 bg-slate-800 rounded w-1/4"></div>
                <div className="h-40 bg-slate-800 rounded-xl"></div>
                <div className="h-40 bg-slate-800 rounded-xl"></div>
              </div>
            )}

            {/* 2. Error Message */}
            {error && (
              <div className="p-5 bg-red-900/30 border border-red-500/30 rounded-xl text-red-200 flex items-start gap-4 animate-in fade-in duration-300">
                <ExclamationTriangleIcon className="h-7 w-7 text-red-500 mt-0.5 shrink-0" />
                <div>
                  <p className="font-semibold text-white">
                    Scan Error Detected
                  </p>
                  <p className="text-slate-300 text-sm mt-1">{error}</p>
                </div>
              </div>
            )}

            {/* 3. Main Results Display */}
            {!loading && results.length > 0 && (
              <div className="animate-in fade-in slide-in-from-bottom-6 duration-500">
                {/* Summary Stats & Download Section */}
                <div className="flex flex-col md:flex-row gap-6 mb-12 items-center md:items-start">
                  {/* Summary Bar */}
                  <div className="flex-grow grid grid-cols-2 md:grid-cols-4 gap-4 w-full">
                    <div className="bg-slate-900 border border-slate-700 p-6 rounded-xl text-center">
                      <p className="text-3xl font-bold text-emerald-400 sm:text-4xl">
                        {results.length}
                      </p>
                      <p className="mt-2 text-sm text-slate-400">
                        Total Findings
                      </p>
                    </div>
                    <div className="bg-red-500/10 border border-red-500/20 p-6 rounded-xl text-center">
                      <p className="text-3xl font-bold text-red-500 sm:text-4xl">
                        {
                          results.filter(
                            (r) =>
                              r.severity === "CRITICAL" ||
                              r.severity === "HIGH",
                          ).length
                        }
                      </p>
                      <p className="mt-2 text-sm text-red-400">
                        Critical / High
                      </p>
                    </div>
                    <div className="bg-yellow-500/10 border border-yellow-500/20 p-6 rounded-xl text-center">
                      <p className="text-3xl font-bold text-yellow-500 sm:text-4xl">
                        {results.filter((r) => r.severity === "MEDIUM").length}
                      </p>
                      <p className="mt-2 text-sm text-yellow-400">
                        Medium Risk
                      </p>
                    </div>
                    <div className="bg-blue-500/10 border border-blue-500/20 p-6 rounded-xl text-center">
                      <p className="text-3xl font-bold text-blue-500 sm:text-4xl">
                        {results.filter((r) => r.severity === "LOW").length}
                      </p>
                      <p className="mt-2 text-sm text-blue-400">Low Risk</p>
                    </div>
                  </div>

                  {/* Export Buttons */}
                  <div className="flex-shrink-0 flex gap-4 w-full md:w-auto">
                    <button
                      onClick={() => downloadReport("pdf")}
                      disabled={!scanId} // Disable if we don't have an ID yet
                      className={`flex-1 rounded-lg border border-slate-700 bg-slate-800/50 px-6 py-3.5 text-center font-semibold transition flex items-center justify-center gap-2 ${
                        !scanId
                          ? "opacity-50 cursor-not-allowed"
                          : "hover:border-slate-600 hover:text-white"
                      }`}
                    >
                      <ArrowDownTrayIcon className="w-5 h-5" /> Export PDF
                    </button>
                    <button
                      onClick={() => downloadReport("csv")}
                      disabled={!scanId}
                      className={`flex-1 rounded-lg border border-slate-700 bg-slate-800/50 px-6 py-3.5 text-center font-semibold transition flex items-center justify-center gap-2 ${
                        !scanId
                          ? "opacity-50 cursor-not-allowed"
                          : "hover:border-slate-600 hover:text-white"
                      }`}
                    >
                      <ArrowDownTrayIcon className="w-5 h-5" /> Export CSV
                    </button>
                  </div>
                </div>

                {/* Vulnerability List Section */}
                <div className="space-y-6">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-5">
                    <h3 className="text-2xl font-bold text-white flex items-baseline gap-2">
                      Detailed Audit Findings
                      <span className="text-sm font-medium tracking-wide uppercase text-slate-500">
                        (tfsec static analysis)
                      </span>
                    </h3>
                  </div>

                  <div className="grid grid-cols-1 gap-6">
                    {results.map((issue, index) => (
                      <VulnerabilityCard key={index} issue={issue} />
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* 4. Success State (No vulnerabilities found) */}
            {!loading && scanPerformed && results.length === 0 && !error && (
              <div className="text-center py-20 px-6 bg-slate-900/50 border-2 border-dashed border-slate-800 rounded-2xl animate-in fade-in duration-500">
                <div className="bg-emerald-500/10 w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-6">
                  <ShieldCheckIcon className="w-10 h-10 text-emerald-400" />
                </div>
                <h3 className="text-2xl font-bold text-white">
                  Infrastructure looks secure!
                </h3>
                <p className="text-slate-400 max-w-sm mx-auto mt-4 text-lg leading-relaxed">
                  Excellent! No critical security misconfigurations or CIS
                  benchmark violations were detected in the .tf files.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default IacScanner;
