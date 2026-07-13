/**
 * Inventory API helpers:
 * - triggerInventoryPull: POST inventory-pull/ (starts async Celery task)
 * - getInventoryRuns: GET inventory-runs/ (latest runs + state)
 */

export function triggerInventoryPull(api, providerId) {
  return api
    .post(`/api/v1/providers/${providerId}/inventory-pull/`)
    .then((res) => res.data);
}

export function getInventoryRuns(api, providerId) {
  return api
    .get(`/api/v1/providers/${providerId}/inventory-runs/`)
    .then((res) => res.data);
}

