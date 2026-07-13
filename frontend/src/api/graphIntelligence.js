export function getGraphIntelligence(api, providerId) {
  return api
    .get(`/api/v1/providers/${providerId}/graph-intelligence/`)
    .then((res) => res.data);
}

export function runGraphAnalysis(api, providerId) {
  return api
    .post(`/api/v1/providers/${providerId}/graph-intelligence/run/`)
    .then((res) => res.data);
}
