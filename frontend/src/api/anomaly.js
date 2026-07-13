export function startAnomalyRun(api, { datasetPath, windowHours = 1, providerId = null }) {
  return api
    .post("/api/v1/anomaly/run/", {
      dataset_path: datasetPath,
      window_hours: windowHours,
      provider_id: providerId,
    })
    .then((res) => res.data);
}

export function listAnomalyRuns(api) {
  return api.get("/api/v1/anomaly/runs/").then((res) => res.data);
}

export function getAnomalyRun(api, runId) {
  return api.get(`/api/v1/anomaly/runs/${runId}/`).then((res) => res.data);
}

export function getAnomalyFindings(api, runId, params = {}) {
  return api
    .get(`/api/v1/anomaly/runs/${runId}/findings/`, { params })
    .then((res) => res.data);
}

export function getAnomalyMetrics(api, runId) {
  return api.get(`/api/v1/anomaly/runs/${runId}/metrics/`).then((res) => res.data);
}

export function getAnomalyEmbeddings(api, runId, window, reduced = true) {
  return api
    .get(`/api/v1/anomaly/runs/${runId}/embeddings/${encodeURIComponent(window)}/`, {
      params: { reduced },
    })
    .then((res) => res.data);
}
