"""
Produces visualisations for colloquium presentation.
Run as standalone script after pipeline completes.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE

from worker.jobs.anomaly_detection.validator import CS_GAD_PAPER_RESULTS


def plot_embedding_tsne(
    embeddings: dict[str, np.ndarray],
    labels: dict[str, bool],
    attack_types: dict[str, str | None],
    window_label: str,
    output_path: str,
) -> None:
    """
    Reduces embeddings to 2D with t-SNE.
    Blue dots = normal, red dots = attack (labelled with attack_type).
    Saves to output_path.
    """
    arns = list(embeddings.keys())
    if len(arns) < 2:
        return

    matrix = np.stack([embeddings[arn] for arn in arns])
    if matrix.shape[0] > 50:
        reducer = TSNE(n_components=2, random_state=42, perplexity=min(30, matrix.shape[0] - 1))
    else:
        reducer = PCA(n_components=2, random_state=42)
    coords = reducer.fit_transform(matrix)

    plt.figure(figsize=(10, 7))
    for idx, arn in enumerate(arns):
        is_attack = labels.get(arn, False)
        color = "red" if is_attack else "blue"
        plt.scatter(coords[idx, 0], coords[idx, 1], c=color, alpha=0.75, s=60)
        if is_attack and attack_types.get(arn):
            plt.annotate(attack_types[arn], (coords[idx, 0], coords[idx, 1]), fontsize=7)

    plt.title(f"Principal Embeddings (t-SNE) — {window_label}")
    plt.xlabel("Dim 1")
    plt.ylabel("Dim 2")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def plot_score_distribution(
    scores: dict[str, float],
    threshold: float,
    labels: dict[str, bool],
    output_path: str,
) -> None:
    """
    Histogram of anomaly scores.
    Red line at threshold.
    Blue bars = normal, red bars = attack.
    """
    normal_scores = [score for arn, score in scores.items() if not labels.get(arn)]
    attack_scores = [score for arn, score in scores.items() if labels.get(arn)]

    plt.figure(figsize=(10, 6))
    bins = 20
    if normal_scores:
        plt.hist(normal_scores, bins=bins, alpha=0.6, color="blue", label="Normal")
    if attack_scores:
        plt.hist(attack_scores, bins=bins, alpha=0.6, color="red", label="Attack")
    if threshold != float("inf"):
        plt.axvline(threshold, color="black", linestyle="--", label=f"Threshold={threshold:.3f}")
    plt.xlabel("Anomaly score")
    plt.ylabel("Count")
    plt.title("Anomaly Score Distribution")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def plot_paper_comparison(per_attack_metrics: dict, output_path: str) -> None:
    """
    Grouped bar chart: for each attack type, paper F1 vs our F1.
    """
    attack_types = sorted(per_attack_metrics.keys())
    if not attack_types:
        return

    paper_f1 = []
    our_f1 = []
    for attack_type in attack_types:
        paper = CS_GAD_PAPER_RESULTS.get(attack_type, {"f1": 0.74})
        paper_f1.append(paper["f1"])
        our_f1.append(per_attack_metrics[attack_type].get("f1_score", 0.0))

    x = np.arange(len(attack_types))
    width = 0.35
    plt.figure(figsize=(12, 6))
    plt.bar(x - width / 2, paper_f1, width, label="CS-GAD Paper F1", color="gray")
    plt.bar(x + width / 2, our_f1, width, label="Our F1", color="blue")
    plt.xticks(x, attack_types, rotation=30, ha="right")
    plt.ylabel("F1 Score")
    plt.title("Per-Attack-Type F1 Comparison")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def generate_all_plots(results_path: str, output_dir: str) -> None:
    with open(results_path, "r", encoding="utf-8") as handle:
        results = json.load(handle)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    embeddings_by_window = results.get("embeddings", {})
    label_map = {
        row["principal_arn"]: bool(row.get("is_attack"))
        for row in results.get("principal_labels", [])
    }
    attack_type_map = {
        row["principal_arn"]: row.get("attack_type")
        for row in results.get("principal_labels", [])
    }
    per_attack_metrics = results.get("per_attack_metrics", {})

    for window_label, embeddings_raw in embeddings_by_window.items():
        embeddings = {arn: np.array(vec, dtype=np.float32) for arn, vec in embeddings_raw.items()}
        labels = {arn: label_map.get(arn, False) for arn in embeddings}
        attack_types = {arn: attack_type_map.get(arn) for arn in embeddings}

        plot_embedding_tsne(
            embeddings,
            labels,
            attack_types,
            window_label,
            str(out / f"tsne_{window_label.replace(':', '-')}.png"),
        )

    combined_scores = {}
    combined_labels = dict(label_map)
    for row in results.get("anomalies", []):
        arn = row["principal_arn"]
        combined_scores[arn] = max(combined_scores.get(arn, 0.0), row.get("final_score", 0.0))
        combined_labels[arn] = bool(row.get("is_attack"))

    window_results = results.get("anomalies", [])
    threshold = window_results[0].get("threshold", float("inf")) if window_results else float("inf")
    if combined_scores or combined_labels:
        plot_score_distribution(
            combined_scores or {arn: 0.0 for arn in combined_labels},
            threshold,
            combined_labels,
            str(out / "score_distribution.png"),
        )

    plot_paper_comparison(per_attack_metrics, str(out / "paper_comparison.png"))


if __name__ == "__main__":
    import sys

    results_file = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\output\anomaly\anomaly_results.json"
    plot_dir = sys.argv[2] if len(sys.argv) > 2 else r"C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\output\anomaly\plots"
    generate_all_plots(results_file, plot_dir)
