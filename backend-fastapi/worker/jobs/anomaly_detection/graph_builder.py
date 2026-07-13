"""
Builds a tripartite NetworkX graph for each time window.
Three node types: Principal (IAM entity), ActionCategory, Service
Two edge types: Principal → ActionCategory, ActionCategory → Service
Edge weights: number of times that connection occurred in the window
"""

from __future__ import annotations

from datetime import datetime

import networkx as nx


def _principal_node_id(arn: str) -> str:
    return f"P::{arn}"


def _action_node_id(category: str) -> str:
    return f"A::{category}"


def _service_node_id(service: str) -> str:
    return f"S::{service}"


def build_graph(events: list[dict]) -> nx.DiGraph:
    """
    Builds tripartite graph from events in one time window.
    Events must already have 'action_category' field.
    Returns NetworkX DiGraph.
    """
    graph = nx.DiGraph()

    principal_meta: dict[str, dict] = {}
    node_counts: dict[str, int] = {}
    node_errors: dict[str, int] = {}
    principal_services: dict[str, set[str]] = {}
    principal_actions: dict[str, set[str]] = {}

    for event in events:
        arn = event.get("principal_arn") or "unknown"
        category = event.get("action_category") or "Unknown"
        service = event.get("event_source") or "unknown"

        p_node = _principal_node_id(arn)
        a_node = _action_node_id(category)
        s_node = _service_node_id(service)

        if p_node not in graph:
            graph.add_node(
                p_node,
                node_type="principal",
                label=arn,
                is_attack=bool(event.get("is_attack")),
                attack_type=event.get("attack_type"),
                call_count=0,
                error_count=0,
                unique_services=0,
                unique_actions=0,
            )
            principal_meta[p_node] = {
                "is_attack": bool(event.get("is_attack")),
                "attack_type": event.get("attack_type"),
            }

        if event.get("is_attack"):
            graph.nodes[p_node]["is_attack"] = True
            if event.get("attack_type"):
                graph.nodes[p_node]["attack_type"] = event.get("attack_type")

        if a_node not in graph:
            graph.add_node(
                a_node,
                node_type="action",
                label=category,
                call_count=0,
                error_count=0,
            )
        if s_node not in graph:
            graph.add_node(
                s_node,
                node_type="service",
                label=service,
                call_count=0,
                error_count=0,
            )

        for node_id in (p_node, a_node, s_node):
            node_counts[node_id] = node_counts.get(node_id, 0) + 1
            if event.get("error_code"):
                node_errors[node_id] = node_errors.get(node_id, 0) + 1

        principal_services.setdefault(p_node, set()).add(service)
        principal_actions.setdefault(p_node, set()).add(category)

        if graph.has_edge(p_node, a_node):
            graph[p_node][a_node]["weight"] += 1
        else:
            graph.add_edge(p_node, a_node, weight=1)

        if graph.has_edge(a_node, s_node):
            graph[a_node][s_node]["weight"] += 1
        else:
            graph.add_edge(a_node, s_node, weight=1)

    for node_id, count in node_counts.items():
        graph.nodes[node_id]["call_count"] = count
        graph.nodes[node_id]["error_count"] = node_errors.get(node_id, 0)

    for p_node, services in principal_services.items():
        graph.nodes[p_node]["unique_services"] = len(services)
        graph.nodes[p_node]["unique_actions"] = len(principal_actions.get(p_node, set()))

    return graph


def build_all_windows(
    windowed_events: dict[datetime, list[dict]],
    min_events_per_window: int = 5,
) -> dict[datetime, nx.DiGraph]:
    """
    Builds one graph per time window.
    Skips windows with fewer than min_events_per_window events.
    Returns dict: window_start → nx.DiGraph
    """
    graphs: dict[datetime, nx.DiGraph] = {}
    for window_start, events in windowed_events.items():
        if len(events) < min_events_per_window:
            continue
        graphs[window_start] = build_graph(events)
    return graphs


def get_principal_nodes(graph: nx.DiGraph) -> list[str]:
    """Returns list of node IDs that have node_type == 'principal'."""
    return [
        node_id
        for node_id, attrs in graph.nodes(data=True)
        if attrs.get("node_type") == "principal"
    ]


def get_graph_stats(graph: nx.DiGraph) -> dict:
    """
    Returns:
      num_nodes, num_edges, num_principals, num_actions, num_services,
      avg_degree, density, num_attack_principals, num_normal_principals
    """
    principals = get_principal_nodes(graph)
    num_actions = sum(1 for _, a in graph.nodes(data=True) if a.get("node_type") == "action")
    num_services = sum(1 for _, a in graph.nodes(data=True) if a.get("node_type") == "service")
    attack_principals = sum(1 for p in principals if graph.nodes[p].get("is_attack"))
    normal_principals = len(principals) - attack_principals
    num_nodes = graph.number_of_nodes()
    num_edges = graph.number_of_edges()
    avg_degree = (2 * num_edges / num_nodes) if num_nodes else 0.0

    return {
        "num_nodes": num_nodes,
        "num_edges": num_edges,
        "num_principals": len(principals),
        "num_actions": num_actions,
        "num_services": num_services,
        "avg_degree": round(avg_degree, 4),
        "density": round(nx.density(graph), 6) if num_nodes > 1 else 0.0,
        "num_attack_principals": attack_principals,
        "num_normal_principals": normal_principals,
    }


if __name__ == "__main__":
    import sys

    from worker.jobs.anomaly_detection.action_categoriser import categorise_events
    from worker.jobs.anomaly_detection.cloudtrail_parser import get_time_windows, parse_directory

    dataset_dir = (
        sys.argv[1]
        if len(sys.argv) > 1
        else r"C:\Users\Admin\Downloads\aws_dataset-main\aws_dataset-main"
    )

    events = categorise_events(parse_directory(dataset_dir))
    windows = get_time_windows(events, window_hours=1)
    graphs = build_all_windows(windows, min_events_per_window=5)

    print(f"Built {len(graphs)} graphs from {len(windows)} windows")
    sample_keys = list(graphs.keys())[:3]
    for window_start in sample_keys:
        stats = get_graph_stats(graphs[window_start])
        print(f"\nWindow {window_start.isoformat()}:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
