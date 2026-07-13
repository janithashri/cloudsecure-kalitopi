export function getRuleEffectiveness(api, providerId) {
  return api
    .get(`/api/v1/providers/${providerId}/findings/rule-effectiveness/`)
    .then((res) => res.data);
}
