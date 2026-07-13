"""
Two anomaly scoring methods:
1. Nearest Neighbour Distance (paper's method): compare to peers in same window
2. Historical Drift (our addition): compare to self over last 14 days
Threshold: mean + 2 * std_dev (paper's formula)
"""

from __future__ import annotations

from collections import defaultdict

import networkx as nx
import numpy as np
from scipy.spatial.distance import cosine, euclidean

# flaws.cloud legitimate actors (environment config, not ground-truth labels)
_FLAWS_LEGITIMATE_IAM_USERS = {"backup", "level6"}
_FLAWS_LEGITIMATE_ROLE_NAMES = {"flaws"}


def is_known_legitimate_flaws_actor(principal_id: str) -> bool:
    """Known legitimate flaws.cloud principals from Summit Route environment."""
    lower = principal_id.lower()
    if not lower.startswith("arn:"):
        return False
    if lower.endswith(":root") or ":assumed-role/flaws" in lower:
        return True
    name = principal_id.split("/")[-1].lower()
    return name in _FLAWS_LEGITIMATE_IAM_USERS or name in _FLAWS_LEGITIMATE_ROLE_NAMES


def _principal_action_categories(graph: nx.DiGraph, principal_arn: str) -> set[str]:
    p_node = f"P::{principal_arn}"
    categories: set[str] = set()
    if p_node not in graph:
        return categories
    for _, action_node in graph.out_edges(p_node):
        label = graph.nodes.get(action_node, {}).get("label")
        if label:
            categories.add(label)
    return categories


def threat_model_score(
    graph: nx.DiGraph,
    principal_arn: str,
    profile: str = "auth_external",
) -> float:
    """
    CloudSecure flaws.cloud threat-model score (no is_attack label).
    Profiles:
      - auth_external: external IP actor performing Authentication (AssumeRole/ConsoleLogin)
      - recon_external: external actor performing GetInfo (e.g. GetBucketAcl scans)
      - full_external: external actor with Authentication, GetInfo, or CreateResource
    """
    if is_known_legitimate_flaws_actor(principal_arn):
        return 0.0
    if not principal_arn.startswith("ip:"):
        return 0.0

    categories = _principal_action_categories(graph, principal_arn)
    if profile == "auth_external":
        return 1.0 if "Authentication" in categories else 0.0
    if profile == "recon_external":
        return 1.0 if "GetInfo" in categories else 0.0
    if profile == "full_external":
        if categories & {"Authentication", "GetInfo", "CreateResource"}:
            return 1.0
    return 0.0


def threat_model_flag(
    graph: nx.DiGraph,
    principal_arn: str,
    profile: str = "auth_external",
    threshold: float = 0.5,
) -> bool:
    return threat_model_score(graph, principal_arn, profile=profile) >= threshold


def baseline_deviation_score(
    principal_embeddings: dict[str, np.ndarray],
) -> dict[str, float]:
    """Distance from embedding to centroid of known legitimate actors in this window."""
    legitimate = [arn for arn in principal_embeddings if is_known_legitimate_flaws_actor(arn)]
    if not legitimate:
        return {arn: 0.0 for arn in principal_embeddings}

    centroid = np.mean(np.stack([principal_embeddings[arn] for arn in legitimate]), axis=0)
    scores: dict[str, float] = {}
    for arn, embedding in principal_embeddings.items():
        if is_known_legitimate_flaws_actor(arn):
            scores[arn] = 0.0
        else:
            scores[arn] = float(euclidean(embedding, centroid))
    return scores


def _principal_services(graph: nx.DiGraph, principal_arn: str) -> set[str]:
    """Return AWS services accessed by a principal in this window."""
    p_node = f"P::{principal_arn}"
    services: set[str] = set()
    if p_node not in graph:
        return services
    for _, action_node in graph.out_edges(p_node):
        action_attrs = graph.nodes.get(action_node, {})
        if action_attrs.get("node_type") != "action":
            continue
        for _, service_node in graph.out_edges(action_node):
            service_attrs = graph.nodes.get(service_node, {})
            if service_attrs.get("node_type") != "service":
                continue
            service_label = service_attrs.get("label") or service_node.removeprefix("S::")
            services.add(service_label)
    return services


def nn_distance_score(
    principal_embeddings: dict[str, np.ndarray],
    graph: nx.DiGraph,
) -> dict[str, float]:
    """
    For each principal, find nearest neighbour among principals
    who accessed the same service in this window (CS-GAD paper).
    Score = Euclidean distance to nearest neighbour.

    If a principal is the ONLY one accessing a service, their score
    is the maximum distance in that window (most anomalous by definition).

    Returns dict: principal_arn → nn_distance_score (float)
    """
    if not principal_embeddings:
        return {}

    arns = list(principal_embeddings.keys())
    service_to_principals: dict[str, set[str]] = defaultdict(set)
    for arn in arns:
        for service in _principal_services(graph, arn):
            service_to_principals[service].add(arn)

    all_distances: list[float] = []
    for i, arn_a in enumerate(arns):
        for arn_b in arns[i + 1 :]:
            all_distances.append(float(euclidean(principal_embeddings[arn_a], principal_embeddings[arn_b])))
    max_distance = max(all_distances) if all_distances else 1.0

    scores: dict[str, float] = {}
    for arn in arns:
        peers: set[str] = set()
        for service in _principal_services(graph, arn):
            peers.update(service_to_principals.get(service, set()))
        peers.discard(arn)

        if not peers:
            scores[arn] = max_distance
            continue

        distances = [
            float(euclidean(principal_embeddings[arn], principal_embeddings[peer]))
            for peer in peers
            if peer in principal_embeddings
        ]
        scores[arn] = min(distances) if distances else max_distance

    return scores


def update_historical_embeddings(
    historical: dict[str, list[np.ndarray]],
    current_embeddings: dict[str, np.ndarray],
    max_history_windows: int = 14 * 24,
) -> dict[str, list[np.ndarray]]:
    """
    Appends current embeddings to history, trims to max_history_windows.
    Returns updated history dict.
    """
    updated = {arn: list(values) for arn, values in historical.items()}
    for arn, embedding in current_embeddings.items():
        history = updated.setdefault(arn, [])
        history.append(np.array(embedding, dtype=np.float32))
        if len(history) > max_history_windows:
            updated[arn] = history[-max_history_windows:]
    return updated


def drift_score(
    current_embeddings: dict[str, np.ndarray],
    historical: dict[str, list[np.ndarray]],
    min_history_windows: int = 3,
) -> dict[str, float]:
    """
    For each principal, compute cosine distance between current embedding
    and mean of historical embeddings.

    If fewer than min_history_windows of history: score = 0.0 (not enough history)

    Returns dict: principal_arn → drift_score (float)
    """
    scores: dict[str, float] = {}
    for arn, current in current_embeddings.items():
        history = historical.get(arn, [])
        if len(history) < min_history_windows:
            scores[arn] = 0.0
            continue
        mean_embedding = np.mean(np.stack(history), axis=0)
        distance = float(cosine(current, mean_embedding))
        scores[arn] = 0.0 if np.isnan(distance) else distance
    return scores


def compute_threshold(scores: dict[str, float], sigma_multiplier: float = 2.0) -> float:
    """
    Computes anomaly threshold: mean + sigma_multiplier × std_dev (CS-GAD paper).
    Returns infinity when fewer than 3 scores exist — flag nobody for that window.
    """
    values = list(scores.values())
    if len(values) < 3:
        return float("inf")
    mean = float(np.mean(values))
    std = float(np.std(values))
    return mean + sigma_multiplier * std


def organizational_peer_nn_score(
    principal_embeddings: dict[str, np.ndarray],
    graph: nx.DiGraph,
) -> dict[str, float]:
    """
    Research extension: nearest neighbour distance to *organizational baseline* peers only.

    Compares each principal to known legitimate actors (from environment inventory,
    not attack labels) who accessed the same AWS service in this window.

    Non-legitimate principals far from the org baseline are anomalous — standard
    UEBA / peer-group anomaly literature (departure from normal cohort).
    """
    if not principal_embeddings:
        return {}

    arns = list(principal_embeddings.keys())
    legitimate = {arn for arn in arns if is_known_legitimate_flaws_actor(arn)}

    all_distances: list[float] = []
    for i, arn_a in enumerate(arns):
        for arn_b in arns[i + 1 :]:
            all_distances.append(float(euclidean(principal_embeddings[arn_a], principal_embeddings[arn_b])))
    max_distance = max(all_distances) if all_distances else 1.0

    scores: dict[str, float] = {}
    for arn in arns:
        if is_known_legitimate_flaws_actor(arn):
            scores[arn] = 0.0
            continue

        org_peers: set[str] = set()
        for service in _principal_services(graph, arn):
            for legit_arn in legitimate:
                if service in _principal_services(graph, legit_arn):
                    org_peers.add(legit_arn)

        if not org_peers:
            scores[arn] = max_distance
            continue

        distances = [
            float(euclidean(principal_embeddings[arn], principal_embeddings[peer]))
            for peer in org_peers
            if peer in principal_embeddings
        ]
        scores[arn] = min(distances) if distances else max_distance

    return scores


def organizational_centroid_score(
    principal_embeddings: dict[str, np.ndarray],
) -> dict[str, float]:
    """Euclidean distance from each principal to the centroid of legitimate actor embeddings."""
    return baseline_deviation_score(principal_embeddings)


def combine_scores(
    *score_maps: dict[str, float],
) -> dict[str, float]:
    """Element-wise max across score maps (CS-GAD multi-signal combination)."""
    keys = set()
    for score_map in score_maps:
        keys |= set(score_map)
    return {arn: max(score_map.get(arn, 0.0) for score_map in score_maps) for arn in keys}


def flag_anomalies_from_combined(
    combined_scores: dict[str, float],
    nn_scores: dict[str, float],
    drift_scores: dict[str, float],
    graph: nx.DiGraph,
    *,
    method: str = "cs_gad_peer",
    org_scores: dict[str, float] | None = None,
) -> list[dict]:
    """Flag principals above mu+2sigma on combined graph scores (no rule bypass)."""
    threshold = compute_threshold(combined_scores)
    flagged: list[dict] = []
    if threshold == float("inf"):
        return flagged

    for arn, final_score in combined_scores.items():
        if final_score <= threshold:
            continue
        p_node = f"P::{arn}"
        attrs = graph.nodes.get(p_node, {})
        flagged.append(
            {
                "principal_arn": arn,
                "final_score": final_score,
                "nn_score": nn_scores.get(arn, 0.0),
                "drift_score": drift_scores.get(arn, 0.0),
                "org_score": (org_scores or {}).get(arn, 0.0),
                "threshold": threshold,
                "is_attack": bool(attrs.get("is_attack")),
                "attack_type": attrs.get("attack_type"),
                "flagged_as_anomaly": True,
                "detection_method": method,
            }
        )

    flagged.sort(key=lambda item: item["final_score"], reverse=True)
    return flagged


def flag_anomalies(
    nn_scores: dict[str, float],
    drift_scores: dict[str, float],
    graph: nx.DiGraph,
) -> list[dict]:
    """Pure CS-GAD: max(peer NN, drift) with mu+2sigma threshold."""
    combined = combine_scores(nn_scores, drift_scores)
    return flag_anomalies_from_combined(
        combined, nn_scores, drift_scores, graph, method="cs_gad_peer"
    )
