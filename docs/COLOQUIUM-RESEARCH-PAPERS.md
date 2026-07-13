# CloudSecure — Research Literature Review (Colloquium / FAANG Prep)

**Purpose:** Papers and datasets to cite when presenting CloudSecure to professors, and directions for **GNN**, **Neo4j GDS**, and **drift detection** extensions.

**Honest framing:** There is **no single paper** that describes *your exact repo* (FastAPI + Cartography + OPA + Resource Explorer delta + Indian compliance tags). Your contribution is an **integrated open-source CSPM** with a clear **research extension path** (GNN on attack graphs, learned path weights vs fixed GDS Dijkstra).

---

## 1. Is there a paper on “exactly our work”?

| Aspect | Closest literature | Your project |
|--------|-------------------|--------------|
| CSPM + graph DB | IJRTI graph-paradigm survey; industry (Prowler Attack Paths, Sysdig) | Same idea, self-hosted, AWS-focused |
| Attack paths | PIGNN, SPGNN-API, Neo4j cyber-APA | Rule/Cypher paths + optional **GDS Dijkstra** (`gds_service.py`) |
| Inventory scan | Cartography (Lyft, open source, not a journal paper) | Resource Explorer + boto3 + OPA Rego |
| Delta / drift | Hash-based delta (yours) + LSTM drift papers (IaC) | Config hash + optional AWS Config signals |
| GNN on cloud vulns | IAM GNN (arXiv 2512.10280), attack-path GNN papers | **Not implemented yet** — primary research opportunity |

---

## 2. Papers to present (tiered for professors)

### Tier A — Must cite (directly related to your graph / attack-path story)

| # | Title | Venue / link | Why cite it |
|---|--------|--------------|-------------|
| A1 | **Physics-Informed Graph Neural Networks for Attack Path Prediction** | *Cybersecurity* MDPI, 2024 — [https://www.mdpi.com/2624-800X/5/2/15](https://www.mdpi.com/2624-800X/5/2/15) | Provides **1,033 environment graphs + attack paths** for ML; PIGNN F1 ~0.93 for full-path prediction. Closest academic dataset for **GNN attack-path** extension on top of your Neo4j graph. |
| A2 | **SPGNN-API: A Transferable Graph Neural Network for Attack Paths Identification and Autonomous Mitigation** | arXiv:2305.19487 — [https://arxiv.org/abs/2305.19487](https://arxiv.org/abs/2305.19487) | GNN for **shortest high-risk paths** + firewall/ZT mitigation; compares to MulVAL. Directly parallels your attack-engine + GDS shortest-path endpoint. |
| A3 | **The graph paradigm: a comprehensive analysis of graph-based technology in cloud security posture** | IJRTI PDF — [https://www.ijrti.org/papers/IJRTI2507138.pdf](https://www.ijrti.org/papers/IJRTI2507138.pdf) | Survey paper on **CSPM + graph databases + attack path analysis**; good for “why graphs for cloud security” slide. |
| A4 | **Graphs for Cybersecurity: Knowledge Graph as Digital Twin** | Neo4j blog / whitepaper — [https://neo4j.com/blog/security/graphs-cybersecurity-knowledge-graph-digital-twin/](https://neo4j.com/blog/security/graphs-cybersecurity-knowledge-graph-digital-twin/) | Industry reference for **GDS Dijkstra + betweenness** on attack graphs — same algorithms family as your `gds.shortestPath.dijkstra.stream`. |

### Tier B — GNN + cloud security (your proposed research direction)

| # | Title | Link | Why cite it |
|---|--------|------|-------------|
| B1 | **Graph Neural Network–Based Adaptive Threat Detection** (Cloud IAM) | arXiv PDF ~2512.10280 — search “GNN Adaptive Threat Detection Cloud IAM” on [arxiv.org](https://arxiv.org) | Models **IAM logs as heterogeneous dynamic graphs**; F1 gains for privilege escalation / lateral movement. Maps to **AWS IAM nodes** after Cartography deep scan. |
| B2 | **Advanced cloud intrusion detection using graph features, transformers, and contrastive learning** | *Scientific Reports*, 2025 — [https://www.nature.com/articles/s41598-025-07956-w](https://www.nature.com/articles/s41598-025-07956-w) | GNN embeddings on **network flow graphs** (NSL-KDD, CIC-IDS2018). Less AWS-config-specific; cite as “GNN in cloud security” background, not as same problem. |
| B3 | **Pro-ZD: Transferable GNN for Proactive Zero-Day Threat Mitigation** | arXiv:2602.07073 — [https://arxiv.org/html/2602.07073v1](https://arxiv.org/html/2602.07073v1) | **Weighted shortest paths** on firewall/policy graphs; >95% accuracy on high-risk connections. Compare to your uniform edge weight `1.0` in GDS projection. |

### Tier C — Drift detection (aligns with your delta scan + AWS Config)

| # | Title | Link | Why cite it |
|---|--------|------|-------------|
| C1 | **AI-Based Drift Detection in Cloud Infrastructure** (LSTM + attention) | IJEDR PDF — [https://rjwave.org/ijedr/papers/IJEDR2504583.pdf](https://rjwave.org/ijedr/papers/IJEDR2504583.pdf) | IaC/config drift; claims **93% accuracy**, **41% FP reduction** with contextual NLP; mentions future **GNN for dependencies** — cite as drift motivation. |
| C2 | **RIVA: Robust Infrastructure by Verification Agents** | arXiv:2603.02345 — [https://arxiv.org/abs/2603.02345](https://arxiv.org/abs/2603.02345) | Multi-agent **LLM drift detection** when IaC tools lie; accuracy recovery 27%→higher with cross-validation. Optional “future work: LLM explains drift” angle. |
| C3 | **LLM-Based Misconfiguration Detection for AWS Serverless (SlsDetector)** | ACM TOSEM / arXiv:2411.00642 — [https://arxiv.org/html/2411.00642v1](https://arxiv.org/html/2411.00642v1) | **110-file AWS SAM dataset** on GitHub; Rego/OPA alternative is LLM. Good for “misconfiguration detection” related work, different surface (serverless YAML). |

### Tier D — Tooling & industry (not peer-reviewed, valid for engineering context)

| # | Resource | Link | Role in presentation |
|---|----------|------|----------------------|
| D1 | **Cartography** (Lyft → CNCF) | [https://github.com/cartography-cncf/cartography](https://github.com/cartography-cncf/cartography) | What powers your **deep scan** graph ingest. |
| D2 | **Prowler Attack Paths** (Cartography + openCypher) | [https://prowler.mintlify.app/user-guide/tutorials/prowler-app-attack-paths](https://prowler.mintlify.app/user-guide/tutorials/prowler-app-attack-paths) | Commercial OSS parallel — privilege escalation Cypher catalog. |
| D3 | **Neo4j GDS Dijkstra** | [https://neo4j.com/docs/graph-data-science/current/algorithms/dijkstra-source-target/](https://neo4j.com/docs/graph-data-science/current/algorithms/dijkstra-source-target/) | Documents what you implemented in `gds_service.py`. |

---

## 3. GDS in CloudSecure vs research (efficiency & novelty)

### What you implement today

From `backend-fastapi/app/services/gds_service.py`:

1. `CALL gds.version()` — plugin check  
2. `gds.graph.project.cypher` — subgraph for one deep-scan `update_tag`  
3. `gds.shortestPath.dijkstra.stream` — source→target with **uniform weight 1.0**  
4. Drop projection after query  

### How research differs

| Topic | Academic / industry best practice | CloudSecure today | Research improvement |
|-------|-----------------------------------|-------------------|----------------------|
| Edge weights | CVSS, exploitability, IAM criticality (SPGNN-API, Pro-ZD) | All edges `1.0` | Learn or rule-based weights → **better path ranking** |
| Path algorithm | GNN predicts paths; Dijkstra baseline | Dijkstra only | Train GNN on PIGNN-style dataset; compare F1/latency vs GDS |
| Graph scope | Full tenant graph | Projected slice by `update_tag` | Good for performance; document **O(V+E)** per projection |
| Centrality | Betweenness for choke points (Neo4j whitepaper) | Not exposed in API | Add `gds.betweenness.stream` for “blast radius hub” UI |
| Efficiency | In-memory GDS catalog | Create/drop projection per API call | **Cache** projection per `(provider_id, update_tag)`; measure ms saved |

### Colloquium sound-bite

> “We use Neo4j GDS Dijkstra as an interpretable baseline. Literature (PIGNN, SPGNN-API) shows GNNs can outperform fixed shortest-path on synthetic attack graphs; our future work is to export Cartography subgraphs into that training pipeline and compare path ranking quality and query latency on real AWS accounts.”

---

## 4. GNN research plan tied to CloudSecure (concrete)

### Problem statement (for professor)

Given a **Cartography-derived AWS security graph** \(G=(V,E)\) and historical misconfigurations / attack patterns, learn a model that:

1. Predicts **high-risk multi-hop paths** (privilege escalation), or  
2. Predicts **probability a resource will become non-compliant** after drift.

### Datasets you can actually use

| Dataset | Size | Fit for CloudSecure |
|---------|------|---------------------|
| **PIGNN attack-path graphs** | 1,033 graphs + paths | **Best** for GNN path prediction experiments |
| **africa-cloud-misconfig-dataset** (Hugging Face) | 10k synthetic configs, 50+ features | Train **misconfiguration classifier** (tabular); merge features from your OPA `input` JSON |
| **SlsDetector evaluation set** (GitHub) | 110 SAM configs | Serverless only; small but real |
| **cloud_posture_checks** (Hugging Face) | 1,290 Prisma rules JSON | LLM/RAG for rule explanation, not GNN |
| **Your own exports** | Neo4j → JSON graphs per deep scan | **Ground truth** = OPA `deny` + manual labels on IAM paths |

### Suggested experiment (publishable as college project / short paper)

1. **Baseline:** GDS Dijkstra + uniform weights (current).  
2. **Rule baseline:** Fixed Cypher attack queries (current `attack_engine`).  
3. **GNN:** GraphSAGE or GAT on PIGNN dataset, then **fine-tune** on 20–50 graphs exported from your deep scans.  
4. **Metrics:** Path overlap with expert paths, Precision@k, inference ms, AWS API cost per scan (unchanged for GNN if offline).

### Papers to read before implementing GNN

1. PIGNN (dataset + architecture) — MDPI 2024  
2. SPGNN-API — arXiv 2305.19487  
3. B1 IAM GNN — arXiv 2512.10280  

---

## 5. Drift detection — literature vs your code

| Approach | Paper / system | CloudSecure |
|----------|----------------|-------------|
| ML time-series | LSTM drift (C1) | Not used |
| IaC text drift | RIVA LLM agents (C2) | Not used |
| **Structural drift** | Hash compare (industry standard) | **`compute_config_hash` / `compute_tag_hash`** + `compute_delta()` |
| Cloud vendor signals | AWS Config | Optional **`config_changed_arns`** in inventory |

**Research gap you can claim:** Combine **hash-based delta** (cheap, deterministic) with **GNN on graph delta** (only re-embed changed nodes/edges) — not in C1/C2 as implemented.

---

## 6. Cost savings (Indian Rupees) — defensible estimates

Use these **only with assumptions stated** in the slide.

### Assumption A — vs commercial CSPM subscription

| Item | Typical USD (SMB, 1 account) | INR (₹83/USD, 2025 approx.) |
|------|------------------------------|-----------------------------|
| Wiz / Orca / Prisma Cloud list | ~$15,000–50,000 / year | **₹12.5L – ₹41.5L / year** |
| CloudSecure | Self-hosted: laptop/cloud ~$50–200/mo infra | **₹5k – ₹17k / month** |

**Claim:** *“For a single-team deployment, avoiding a commercial CNAPP seat can save on the order of **₹10–40 lakh per year** in license fees; tradeoff is self-operated engineering time.”*

### Assumption B — delta scan reduces AWS API cost

| Item | Full scan | Delta scan (steady state) |
|------|-----------|---------------------------|
| Describe* calls per resource | 100% resources | ~5–20% changed (typical) |
| API charges (varies by service) | Higher | **~80–95% fewer** read calls after first scan |

Example: If monthly AWS read-style API spend attributable to scanner is **₹8,000**, delta may reduce to **₹1,000–₹2,000** → **~₹6k–₹7k/month saved** (order-of-magnitude; measure with CloudTrail billing).

### Assumption C — engineer time (India)

| Activity | Hours saved / month | ₹/hr (mid SDE) | INR |
|----------|---------------------|------------------|-----|
| Unified dashboard vs manual console checks | 10–20 h | ₹800–1,500 | **₹8k – ₹30k** |

**Do not claim** exact savings without your own measurements — run:

```sql
SELECT AVG((stats->>'delta_count')::int), COUNT(*) FROM api_inventoryrun WHERE state='completed';
```

and AWS Cost Explorer for API-heavy services after 1 month.

---

## 7. Kaggle dataset evaluation

**Dataset:** [Microservices Bottleneck Detection Dataset](https://www.kaggle.com/datasets/gagansomashekar/microservices-bottleneck-detection-dataset) (Gagan Somashekar)

### Verdict: **Not relevant** to CloudSecure CSPM (do not cite as core related work)

| Criterion | Microservices bottleneck dataset | CloudSecure |
|-----------|----------------------------------|-------------|
| Domain | **Performance** (latency, CPU, service mesh bottlenecks) | **Security posture** (misconfig, IAM, compliance) |
| Labels | Bottleneck location / performance classes | OPA `deny` findings, severity, CIS/DPDP |
| Graph | Service call graph / metrics | AWS asset graph (Cartography / Resource nodes) |
| Data source | APM-style microservice metrics | AWS APIs, Resource Explorer |
| Use in GNN drift/vuln paper | Weak | Use PIGNN or cloud-misconfig HF datasets instead |

### When you *could* mention it (one sentence)

> “Performance-oriented microservice graphs (Kaggle bottleneck datasets) solve a different problem than cloud security graphs; we focus on IAM reachability and misconfiguration attack paths.”

### If professor asks “any attached paper?”

The Kaggle page is a **dataset**, not a peer-reviewed paper. For colloquium, replace with **Tier A/B papers** above.

---

## 8. Comparison table for slides (“Us vs literature”)

| Dimension | Typical paper / product | CloudSecure |
|-----------|-------------------------|-------------|
| Cloud | Often network IDS or generic graphs | **AWS** S3/EC2/IAM/RDS/KMS/CloudTrail |
| Compliance | CIS (global) | **CIS + DPDP + RBI + SBE** (India angle — differentiation) |
| Policy engine | ML or LLM | **OPA/Rego** (deterministic, auditable) |
| Discovery | Static graph only | **Resource Explorer + delta hashes** |
| Deep graph | Cartography / Prowler | Cartography in **optional** worker |
| Path finding | GNN or Dijkstra | **Cypher + GDS Dijkstra** (GNN = future) |
| Tenancy | Often single-tenant experiments | **Multi-tenant** Postgres isolation |
| Cost model | Not discussed | **Self-hosted** cost story (Section 6) |

---

## 9. Suggested colloquium structure (20–25 min)

1. **Problem** — Cloud misconfig + lateral movement (cite IJRTI A3).  
2. **Related work** — Cartography, Prowler, PIGNN, SPGNN-API (2 slides).  
3. **Our system** — architecture diagram (1 slide).  
4. **Delta + OPA** — how drift is detected today (1 slide).  
5. **GDS shortest path** — demo + complexity (1 slide).  
6. **Gap** — no GNN yet; proposal with PIGNN dataset (2 slides).  
7. **Evaluation plan** — metrics, datasets, ethical use of customer graphs.  
8. **Cost / India compliance** — differentiation (1 slide).  
9. **Q&A** — Celery/Cartography engineering story optional.

---

## 10. BibTeX snippets (copy to report)

```bibtex
@article{pignn2024,
  title={Physics-Informed Graph Neural Networks for Attack Path Prediction},
  journal={Cybersecurity},
  year={2024},
  url={https://www.mdpi.com/2624-800X/5/2/15}
}

@article{spgnn2023,
  title={SPGNN-API: A Transferable Graph Neural Network for Attack Paths Identification and Autonomous Mitigation},
  journal={arXiv preprint arXiv:2305.19487},
  year={2023}
}

@article{graphcspm2025,
  title={The graph paradigm: a comprehensive analysis of graph-based technology in cloud security posture},
  journal={International Journal of Research and Technology Innovation},
  year={2025},
  url={https://www.ijrti.org/papers/IJRTI2507138.pdf}
}

@article{driftlstm2025,
  title={AI-Based Drift Detection In Cloud Infrastructure},
  journal={International Journal of Engineering and Data Research},
  year={2025},
  url={https://rjwave.org/ijedr/papers/IJEDR2504583.pdf}
}

@inproceedings{slsdetector2025,
  title={LLM-Based Misconfiguration Detection for AWS Serverless Computing},
  journal={ACM Transactions on Software Engineering and Methodology},
  year={2025},
  doi={10.1145/3745766}
}
```

---

## 11. What to tell your professor in one paragraph

CloudSecure sits at the intersection of **graph-based CSPM** (surveyed in IJRTI 2025) and **practical AWS tooling** (Cartography, OPA, Resource Explorer). Our current attack-path feature uses **Neo4j GDS Dijkstra** as a transparent baseline; recent research (PIGNN 2024, SPGNN-API 2023, IAM-GNN 2025) shows **graph neural networks** can improve path prediction and zero-day risk ranking on dedicated datasets—this is the natural **next research phase** for the project. Configuration **drift** in our system is handled deterministically via **content hashes and AWS Config signals**, complementary to ML drift papers (LSTM, LLM agents). The attached **Kaggle microservices bottleneck dataset is not applicable**; we should use **PIGNN attack-path graphs** or **Hugging Face cloud-misconfig datasets** instead. Cost savings for Indian deployments are primarily **avoided commercial CNAPP licensing** (order ₹10–40L/year for SMB assumptions) plus **reduced AWS read API** from delta scanning, which we can quantify empirically.

---

*Last updated for colloquium prep — verify URLs before final submission.*
