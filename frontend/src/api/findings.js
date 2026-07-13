/**
 * Findings API — list, summary, suppress.
 * Use with useAuth().api (axios instance with token).
 */

export function getFindings(api, providerId, params = {}) {
  const cleaned = Object.fromEntries(
    Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "")
  );
  const q = new URLSearchParams(cleaned).toString();
  const url = `/api/v1/providers/${providerId}/findings/${q ? `?${q}` : ""}`;
  return api.get(url).then((res) => res.data);
}

export function getFindingsSummary(api, providerId) {
  return api.get(`/api/v1/providers/${providerId}/findings/summary/`).then((res) => res.data);
}

export function suppressFinding(api, findingId) {
  return api.patch(`/api/v1/findings/${findingId}/suppress/`);
}
