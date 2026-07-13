import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "../context/AuthContext";
import {
  getAnomalyEmbeddings,
  getAnomalyFindings,
  getAnomalyMetrics,
  getAnomalyRun,
  listAnomalyRuns,
  startAnomalyRun,
} from "../api/anomaly";
import EmbeddingScatterPlot from "../components/EmbeddingScatterPlot";
import AnomalyEntityTable from "../components/AnomalyEntityTable";
import AttackTypeBreakdown from "../components/AttackTypeBreakdown";

const DEFAULT_DATASET = "/data/aws_dataset";

function MetricCard({ label, value }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-xl font-semibold text-white">
        {value == null ? "—" : typeof value === "number" ? value.toFixed(2) : value}
      </p>
    </div>
  );
}

export default function AnomalyPage() {
  const { api } = useAuth();
  const [datasetPath, setDatasetPath] = useState(DEFAULT_DATASET);
  const [runs, setRuns] = useState([]);
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [runDetail, setRunDetail] = useState(null);
  const [findings, setFindings] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [embeddings, setEmbeddings] = useState([]);
  const [selectedWindow, setSelectedWindow] = useState("");
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);

  const refreshRuns = useCallback(() => {
    listAnomalyRuns(api)
      .then((data) => {
        setRuns(data);
        if (!selectedRunId && data.length) setSelectedRunId(data[0].id);
      })
      .catch(() => setRuns([]));
  }, [api, selectedRunId]);

  useEffect(() => {
    refreshRuns();
  }, [refreshRuns]);

  const windowOptions = useMemo(() => {
    const keys = Object.keys(runDetail?.stats?.embeddings || {});
    return keys.sort();
  }, [runDetail]);

  useEffect(() => {
    if (!selectedRunId) return;
    setLoading(true);
    setError(null);
    Promise.all([
      getAnomalyRun(api, selectedRunId),
      getAnomalyFindings(api, selectedRunId, { limit: 100 }),
      getAnomalyMetrics(api, selectedRunId),
    ])
      .then(([run, findingRows, metricsData]) => {
        setRunDetail(run);
        setFindings(findingRows);
        setMetrics(metricsData);
        const windows = Object.keys(run.stats?.embeddings || {});
        const nextWindow = windows.includes(selectedWindow) ? selectedWindow : windows[0] || "";
        setSelectedWindow(nextWindow);
      })
      .catch((e) => setError(e?.response?.data?.detail || "Failed to load anomaly run."))
      .finally(() => setLoading(false));
  }, [api, selectedRunId]);

  useEffect(() => {
    if (!selectedRunId || !selectedWindow) {
      setEmbeddings([]);
      return;
    }
    getAnomalyEmbeddings(api, selectedRunId, selectedWindow, true)
      .then((data) => setEmbeddings(data.points || []))
      .catch(() => setEmbeddings([]));
  }, [api, selectedRunId, selectedWindow]);

  const handleRun = () => {
    if (running) return;
    setRunning(true);
    setError(null);
    startAnomalyRun(api, { datasetPath, windowHours: 1 })
      .then(({ run_id }) => {
        setSelectedRunId(run_id);
        const poll = () =>
          getAnomalyRun(api, run_id).then((run) => {
            if (run.status === "running" || run.status === "queued") {
              return new Promise((resolve) => setTimeout(resolve, 2000)).then(poll);
            }
            if (run.status === "failed") {
              const msg = run.stats?.error || "Anomaly run failed.";
              setError(msg);
            }
            setRunDetail(run);
            return refreshRuns();
          });
        return poll();
      })
      .catch((e) => setError(e?.response?.data?.detail || "Failed to start anomaly run."))
      .finally(() => setRunning(false));
  };

  const overall = metrics?.overall || {};

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Anomaly Detection</h1>
          <p className="mt-1 text-sm text-slate-400">
            Graph-based IAM anomaly detection (Node2Vec + CS-GAD scoring)
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="text"
            value={datasetPath}
            onChange={(e) => setDatasetPath(e.target.value)}
            className="w-96 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            placeholder="/data/aws_dataset"
          />
          <p className="w-full text-xs text-slate-500">
            Docker: use <code className="text-slate-400">/data/aws_dataset</code> and set{" "}
            <code className="text-slate-400">ANOMALY_DATASET_HOST_PATH</code> in <code className="text-slate-400">.env</code>
          </p>
          <button
            type="button"
            onClick={handleRun}
            disabled={running}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {running ? "Starting…" : "Run on Dataset"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <label className="text-sm text-slate-400">Run</label>
        <select
          value={selectedRunId || ""}
          onChange={(e) => setSelectedRunId(Number(e.target.value))}
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
        >
          {runs.map((run) => (
            <option key={run.id} value={run.id}>
              #{run.id} — {run.status} — {run.total_flagged} flagged
            </option>
          ))}
        </select>
        {runDetail && (
          <span className="text-sm text-slate-500">
            {runDetail.status} · {runDetail.total_windows} windows ·{" "}
            {runDetail.stats?.total_events ?? 0} events
          </span>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Results Summary</h2>
          <div className="grid grid-cols-2 gap-3">
            <MetricCard label="F1" value={overall.f1_score ?? runDetail?.overall_f1} />
            <MetricCard label="Precision" value={overall.precision ?? runDetail?.overall_precision} />
            <MetricCard label="Recall" value={overall.recall ?? runDetail?.overall_recall} />
            <MetricCard label="FPR" value={overall.false_positive_rate ?? runDetail?.overall_fpr} />
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
              Embedding Scatter Plot
            </h2>
            <select
              value={selectedWindow}
              onChange={(e) => setSelectedWindow(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-white"
            >
              {windowOptions.map((window) => (
                <option key={window} value={window}>
                  {window}
                </option>
              ))}
            </select>
          </div>
          <EmbeddingScatterPlot
            points={embeddings}
            title={selectedWindow ? `Window ${selectedWindow}` : "Principal Embeddings"}
          />
        </div>
      </div>

      <AttackTypeBreakdown
        paperComparison={metrics?.paper_comparison || []}
        perAttackMetrics={metrics?.per_attack_type || {}}
      />

      {loading ? (
        <div className="text-sm text-slate-500">Loading run data…</div>
      ) : (
        <AnomalyEntityTable findings={findings} />
      )}
    </div>
  );
}
