export function getCustomRules(api, providerId) {
  const q = providerId ? `?provider_id=${encodeURIComponent(providerId)}` : "";
  return api.get(`/api/v1/custom-rules/${q}`).then((res) => res.data);
}

export function createCustomRule(api, payload) {
  return api.post("/api/v1/custom-rules/", payload).then((res) => res.data);
}
