"""
Runs Node2Vec on a tripartite NetworkX graph and returns embeddings.
Uses gensim Word2Vec on random walks (CS-GAD paper hyperparameters).
Returns dict: node_id → numpy array of shape (128,)
"""

from __future__ import annotations

import logging
import random
from datetime import datetime

import networkx as nx
import numpy as np
from gensim.models import Word2Vec
from tqdm import tqdm

logger = logging.getLogger(__name__)

NODE2VEC_PARAMS = {
    "dimensions": 128,
    "walk_length": 20,
    "num_walks": 100,
    "p": 1,
    "q": 0.5,
    "workers": 4,
    "window": 5,
    "min_count": 1,
    "batch_words": 4,
}


def _biased_next(current: str, previous: str | None, graph: nx.Graph, q: float, p: float) -> str | None:
    neighbours = list(graph.neighbors(current))
    if not neighbours:
        return None
    if previous is None:
        return random.choice(neighbours)

    weights: list[float] = []
    for neighbour in neighbours:
        if neighbour == previous:
            weights.append(1.0 / p)
        elif graph.has_edge(previous, neighbour):
            weights.append(1.0)
        else:
            weights.append(1.0 / q)

    total = sum(weights)
    if total <= 0:
        return random.choice(neighbours)
    pick = random.uniform(0, total)
    cumulative = 0.0
    for neighbour, weight in zip(neighbours, weights):
        cumulative += weight
        if pick <= cumulative:
            return neighbour
    return neighbours[-1]


def _generate_walks(graph: nx.Graph, params: dict) -> list[list[str]]:
    walks: list[list[str]] = []
    nodes = list(graph.nodes())
    for _ in range(params["num_walks"]):
        random.shuffle(nodes)
        for start in nodes:
            walk = [start]
            previous: str | None = None
            current = start
            for _step in range(params["walk_length"] - 1):
                nxt = _biased_next(current, previous, graph, params["q"], params["p"])
                if nxt is None:
                    break
                walk.append(nxt)
                previous, current = current, nxt
            walks.append([str(node) for node in walk])
    return walks


def run_node2vec(
    graph: nx.DiGraph,
    params: dict | None = None,
    seed: int = 42,
) -> dict[str, np.ndarray]:
    """
    Runs Node2Vec on graph.
    Returns dict: node_id → embedding array of shape (128,)
    Only returns embeddings for nodes that exist in the graph.
    """
    params = params or NODE2VEC_PARAMS
    if graph.number_of_nodes() <= 1:
        logger.warning("Graph has <= 1 node; skipping Node2Vec")
        return {}

    undirected = graph.to_undirected()
    if undirected.number_of_nodes() <= 1:
        logger.warning("Undirected graph has <= 1 node; skipping Node2Vec")
        return {}

    try:
        random.seed(seed)
        walks = _generate_walks(undirected, params)
        if not walks:
            return {}
        model = Word2Vec(
            sentences=walks,
            vector_size=params["dimensions"],
            window=params["window"],
            min_count=params["min_count"],
            batch_words=params["batch_words"],
            workers=params["workers"],
            sg=1,
            seed=seed,
        )
    except Exception as exc:
        logger.warning("Node2Vec failed: %s", exc)
        return {}

    embeddings: dict[str, np.ndarray] = {}
    for node_id in graph.nodes:
        key = str(node_id)
        if key in model.wv:
            embeddings[node_id] = model.wv[key].astype(np.float32)
    return embeddings


def run_all_windows(
    windowed_graphs: dict[datetime, nx.DiGraph],
    params: dict | None = None,
    seed: int = 42,
) -> dict[datetime, dict[str, np.ndarray]]:
    """
    Runs Node2Vec on every graph window.
    Returns dict: window_start → {node_id → embedding}
    Shows progress bar with tqdm.
    """
    params = params or NODE2VEC_PARAMS
    results: dict[datetime, dict[str, np.ndarray]] = {}
    for window_start, graph in tqdm(windowed_graphs.items(), desc="Node2Vec windows"):
        results[window_start] = run_node2vec(graph, params=params, seed=seed)
    return results


def get_principal_embeddings(
    embeddings: dict[str, np.ndarray],
    graph: nx.DiGraph,
) -> dict[str, np.ndarray]:
    """
    Filters embeddings to only principal nodes.
    Returns dict: principal_arn → embedding
    """
    principal_embeddings: dict[str, np.ndarray] = {}
    for node_id, vector in embeddings.items():
        attrs = graph.nodes.get(node_id, {})
        if attrs.get("node_type") != "principal":
            continue
        arn = attrs.get("label") or node_id.removeprefix("P::")
        principal_embeddings[arn] = vector
    return principal_embeddings


if __name__ == "__main__":
    import sys

    from worker.jobs.anomaly_detection.action_categoriser import categorise_events
    from worker.jobs.anomaly_detection.cloudtrail_parser import get_time_windows, parse_directory
    from worker.jobs.anomaly_detection.graph_builder import build_all_windows

    dataset_dir = (
        sys.argv[1]
        if len(sys.argv) > 1
        else r"C:\Users\Admin\Downloads\aws_dataset-main\aws_dataset-main"
    )

    events = categorise_events(parse_directory(dataset_dir))
    windows = get_time_windows(events, window_hours=1)
    graphs = build_all_windows(windows, min_events_per_window=5)
    sample_graphs = dict(list(graphs.items())[:3])
    embeddings_by_window = run_all_windows(sample_graphs)

    for window_start, embeddings in embeddings_by_window.items():
        graph = sample_graphs[window_start]
        principals = get_principal_embeddings(embeddings, graph)
        print(f"\nWindow {window_start.isoformat()}:")
        print(f"  Total node embeddings: {len(embeddings)}")
        print(f"  Principal embeddings: {len(principals)}")
        if embeddings:
            first = next(iter(embeddings.values()))
            print(f"  Embedding shape: {first.shape}")
