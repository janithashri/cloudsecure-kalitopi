export function getCartographyGraph(api, providerId, label = null, scanId = null) {
  const params = new URLSearchParams();
  if (label) params.set("label", label);
  if (scanId) params.set("scan_id", scanId);
  const qs = params.toString() ? `?${params.toString()}` : "";
  return api
    .get(`/api/v1/providers/${providerId}/graph/cartography/${qs}`)
    .then((res) => res.data);
}

export function getAttackQueries(api) {
  return api.get("/api/auth/attack-engine/queries/").then((res) => res.data);
}

export function runAttackEngine(api, providerId, scanId = null) {
  const payload = scanId ? { scan_id: scanId } : {};
  return api
    .post(`/api/v1/providers/${providerId}/attack-engine/run/`, payload)
    .then((res) => res.data);
}

export function getAttackQueryGraph(api, providerId, queryId, scanId = null) {
  const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : "";
  return api
    .get(`/api/v1/providers/${providerId}/attack-engine/query/${queryId}/${qs}`)
    .then((res) => res.data);
}
