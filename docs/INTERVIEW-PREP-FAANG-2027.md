# CloudSecure — FAANG SDE Interview Prep (2027)

**Project:** Open-source CSPM (Cloud Security Posture Management) for AWS  
**Stack:** FastAPI, Celery, Valkey/Redis, PostgreSQL, Neo4j, OPA/Rego, React, Docker, boto3, Cartography (deep scan)  
**Use this doc for:** OOP, DBMS, OS, CN, core CS, system design, and project-specific Q&A with model answers.

---

## Table of contents

1. [30-second & 2-minute pitch](#1-30-second--2-minute-pitch)
2. [Architecture cheat sheet](#2-architecture-cheat-sheet)
3. [OOP — theory + CloudSecure mapping](#3-oop--theory--cloudsecure-mapping)
4. [DBMS — theory + CloudSecure mapping](#4-dbms--theory--cloudsecure-mapping)
5. [Operating systems — theory + CloudSecure mapping](#5-operating-systems--theory--cloudsecure-mapping)
6. [Computer networks — theory + CloudSecure mapping](#6-computer-networks--theory--cloudsecure-mapping)
7. [Core CS & distributed systems](#7-core-cs--distributed-systems)
8. [Project deep-dive Q&A (with solutions)](#8-project-deep-dive-qa-with-solutions)
9. [System design questions](#9-system-design-questions)
10. [Coding / DSA angles from the project](#10-coding--dsa-angles-from-the-project)
11. [Behavioral hooks (STAR)](#11-behavioral-hooks-star)
12. [Quick revision checklist](#12-quick-revision-checklist)

---

## 1. 30-second & 2-minute pitch

### 30 seconds

> “I built **CloudSecure**, a self-hosted CSPM platform for AWS. Tenants connect accounts via cross-account IAM roles; we discover resources with **AWS Resource Explorer**, fetch detailed configs with **boto3**, evaluate **350+ Rego policies** in **OPA**, and store findings in **PostgreSQL**. Inventory runs asynchronously on **Celery** with **delta scanning** so we only re-fetch changed resources. For attack-path analysis we ingest a richer graph with **Cartography** into **Neo4j** and run Cypher queries. The UI is **React**; the API is **FastAPI** with token auth and strict **multi-tenant** isolation.”

### 2 minutes (add tradeoffs)

- **Why async workers?** Scans are long I/O-bound (AWS APIs); API stays responsive; failures retry with Celery.
- **Why OPA?** Policies as code (Rego), versioned, testable; engine separate from app logic.
- **Why two graphs?** Lightweight inventory graph (Resource nodes) for dashboard; Cartography graph for MITRE-style attack paths (heavier, optional deep scan).
- **Hardest bug I fixed:** Celery worker crashed importing Cartography on the inventory image — fixed with conditional imports and separate `celery-deep-scan` worker/queue.

---

## 2. Architecture cheat sheet

```
[React :3000] --HTTP/JSON--> [FastAPI :8000] --SQL--> [PostgreSQL]
        |                          |
        |                          +--> [OPA :8181]  (policy evaluate)
        |                          +--> [Neo4j :7687] (graph read)
        |
[FastAPI] --enqueue--> [Valkey/Redis] <--consume-- [Celery: inventory queue]
                                              <-- [Celery Beat: periodic]
                                              <-- [Celery deep_scan queue + Cartography]
```

| Component | Role |
|-----------|------|
| **FastAPI** | REST API, auth, provider CRUD, trigger scans, read findings |
| **Celery** | `perform_inventory_pull_task`, rule evaluation, deep scan job |
| **PostgreSQL** | Users, tenants, providers, inventory runs, findings, resource hashes |
| **Neo4j** | Resource relationships, attack-path / deep-scan graph |
| **OPA** | Rego policy evaluation (`deny` rules) |
| **Valkey** | Celery broker + result backend + schedule hash |
| **boto3** | STS AssumeRole, Resource Explorer, per-service describe APIs |

---

## 3. OOP — theory + CloudSecure mapping

### 3.1 Four pillars (with interview answers)

| Pillar | Definition | CloudSecure example |
|--------|------------|---------------------|
| **Encapsulation** | Hide internal state; expose operations | `repositories.py` hides SQL; routers only call `repo.get_provider_for_tenant()` |
| **Abstraction** | Simplify complex subsystem | `FETCHER_MAP` maps resource type → fetch function; inventory code doesn’t know S3 vs EC2 details |
| **Inheritance** | Reuse via IS-A | SQLAlchemy `Base` models; optional class-based fetchers |
| **Polymorphism** | Same interface, many implementations | Different fetchers, same signature; OPA evaluates any Rego package via same `evaluate()` |

**Q: Is your project OOP-heavy?**  
**A:** Pragmatic mix: **SQLAlchemy ORM** for data, **functional modules** for AWS fetchers and Celery tasks. Interview line: *“Domain entities are modeled as ORM classes; orchestration is procedural for clarity and testability in I/O-heavy paths.”*

---

### 3.2 SOLID (applied to CloudSecure)

**S — Single Responsibility**  
- `opa_client.py` → only OPA HTTP.  
- `neo4j_writer.py` → only graph writes for inventory.  
- `providers.py` router → HTTP + validation, not AWS logic.

**O — Open/Closed**  
- Add new AWS service: add fetcher + Rego rules without changing inventory loop core.  
- `FETCHER_MAP` extension point.

**L — Liskov Substitution**  
- Any fetcher returning normalized config dict can plug into delta pipeline.

**I — Interface Segregation**  
- FastAPI `Depends(get_current_tenant)` — endpoints that need tenant don’t pull full user graph unnecessarily.

**D — Dependency Inversion**  
- API depends on `get_db` / repository abstractions, not raw SQL in routers.  
- Settings via `get_settings()` (config injection).

---

### 3.3 OOP interview questions (general + project)

| # | Question | Model answer |
|---|----------|----------------|
| 1 | Difference between abstraction and encapsulation? | Abstraction = *what* you expose (e.g. `trigger scan`). Encapsulation = *hiding* how (Celery task + AWS calls inside worker). |
| 2 | Composition vs inheritance? | CloudSecure prefers **composition**: inventory pipeline composes fetcher + hasher + OPA evaluator + DB repo. Inheritance only via ORM base. |
| 3 | Why not OOP everywhere? | I/O pipelines (scan loop) are clearer as functions; forcing classes adds boilerplate. |
| 4 | Design a `Policy` class hierarchy? | Could have `Policy` ABC with `evaluate(config) -> Finding[]`; we use **OPA** instead to avoid redeploying Python for new rules. |
| 5 | Static vs dynamic polymorphism? | Static: overloaded methods (N/A in Python). Dynamic: fetcher selected at runtime from `FETCHER_MAP[resource_type]`. |
| 6 | Coupling vs cohesion? | High cohesion in `rule_engine/`; loose coupling between API and worker via **message queue**. |
| 7 | Factory pattern in your project? | `get_client(account_id, role_name, service, region)` builds boto3 clients after STS — factory for AWS clients. |
| 8 | Singleton? | `get_settings()` cached settings; Neo4j driver per tenant — careful singleton (connection pooling). |
| 9 | MVC in your app? | **Model:** SQLAlchemy ORM. **View:** React. **Controller:** FastAPI routers. |
| 10 | How do you test without AWS? | Mock boto3 / OPA HTTP; unit test `compute_delta`, hashing, Rego with fixture JSON. |

---

## 4. DBMS — theory + CloudSecure mapping

### 4.1 Schema mental model (PostgreSQL)

| Table (concept) | Purpose |
|-----------------|--------|
| `auth_user`, `authtoken_token` | Login, API tokens |
| `api_tenant`, `api_userprofile` | Multi-tenant boundary |
| `api_provider` | AWS account + role name per tenant |
| `api_inventoryrun` | Scan run state, stats JSON |
| `api_finding` | Open/closed misconfigurations |
| `api_resourcestatehash` | Per-ARN config/tag hashes for delta |
| `api_deepscan` | Cartography job state, `update_tag` |

**Neo4j** is a separate **graph DB** (not relational) — nodes/edges for resources and attack paths.

---

### 4.2 DBMS interview questions (with solutions)

| # | Question | Solution / CloudSecure tie-in |
|---|----------|-------------------------------|
| 1 | **ACID?** | **A:** all-or-nothing commit (create inventory run + enqueue should be consistent; we create run in worker). **C:** FK tenant_id on providers. **I:** isolation between tenants via `WHERE tenant_id = ?`. **D:** committed findings survive crash. |
| 2 | **Why PostgreSQL + Neo4j?** | Postgres: transactional findings, users, runs. Neo4j: path queries (privilege escalation chains) are expensive in SQL; graph native. |
| 3 | **Normalization?** | Providers normalized per tenant; findings reference `inventory_run_id`; avoid duplicating full config in findings (store ARN + rule metadata). |
| 4 | **Index strategy?** | Index `(provider_id, state)` on inventory runs; `(provider_id, status)` on findings; token key unique on `authtoken_token`. |
| 5 | **N+1 query problem?** | Use SQLAlchemy `joinedload` when listing findings with provider; paginate findings API. |
| 6 | **Optimistic vs pessimistic locking?** | `has_running_inventory_run` prevents duplicate concurrent scans (pessimistic at business level). Could use row lock `SELECT FOR UPDATE` on provider. |
| 7 | **SQL vs NoSQL for findings?** | Findings need joins, filters, compliance reports → SQL fits. Graph relationships → Neo4j. |
| 8 | **CAP theorem?** | Single-region self-hosted: favor **CP** for Postgres. Celery at-least-once → idempotent task design. |
| 9 | **Sharding tenants?** | Today: row-level `tenant_id`. Scale: schema per tenant or shard by `tenant_id`. |
| 10 | **Migrations?** | Django migrations on shared schema; FastAPI uses same tables (`api_*`). |
| 11 | **What is a transaction in your scan flow?** | Per-resource upsert finding can commit independently; run finalization updates `inventoryrun.state` in one transaction. |
| 12 | **Deadlock scenario?** | Two workers updating same resource row — mitigate with unique constraint on (provider, arn, rule_id) and upsert. |
| 13 | **Explain delta table design** | `ResourceStateHash` stores SHA-256 of normalized config/tags; compare with current scan to compute new/changed/deleted. |
| 14 | **B+ tree vs hash index?** | B+ tree for range queries (`started_at DESC` on runs); hash for exact token lookup. |
| 15 | **Replication?** | Production: Postgres read replica for dashboard; primary for writes; Neo4j causal cluster if HA needed. |

---

### 4.3 Sample SQL you should be able to write

```sql
-- Open critical findings for provider 1
SELECT rule_name, resource_arn, severity
FROM api_finding
WHERE provider_id = 1 AND status = 'OPEN' AND severity IN ('CRITICAL', 'HIGH');

-- Last 5 inventory runs
SELECT id, state, started_at, stats
FROM api_inventoryrun
WHERE provider_id = 1
ORDER BY started_at DESC
LIMIT 5;
```

---

## 5. Operating systems — theory + CloudSecure mapping

| # | Question | Solution / CloudSecure tie-in |
|---|----------|-------------------------------|
| 1 | **Process vs thread?** | Celery **prefork** workers = processes; concurrency inside worker for I/O. Beat scheduler separate process. |
| 2 | **Why separate Celery containers?** | Isolation: deep-scan OOM doesn’t kill inventory worker; different images (Cartography only on deep-scan). |
| 3 | **Docker vs VM?** | Compose runs cgroups/namespaces per service; shares host kernel; faster than full VM. |
| 4 | **CPU-bound vs I/O-bound?** | Inventory scan is **I/O-bound** (AWS APIs) → async tasks, multiple workers, backoff. |
| 5 | **Scheduling?** | Celery Beat every 30 min; Linux CFS schedules container processes. |
| 6 | **Deadlock (OS)?** | Worker holds DB connection waiting on AWS; mitigated timeouts on boto3/OPA HTTP. |
| 7 | **Memory management?** | Neo4j + Cartography hungry; limit Docker Desktop RAM; separate deep-scan worker. |
| 8 | **Page fault / thrashing?** | Low RAM on laptop → Docker kills engine; relevant to your Windows dev setup. |
| 9 | **Syscalls in your stack?** | Container makes socket syscalls for HTTP, DB, Redis; host kernel mediates. |
| 10 | **Fork copy-on-write?** | Celery prefork: child processes COW parent memory until write. |
| 11 | **Signals?** | Deep scan cancel: `revoke(task_id, terminate=True, signal='SIGTERM')`. |
| 12 | **File descriptors?** | Many concurrent HTTP connections to AWS → ulimit / connection pooling. |
| 13 | **Mutex vs semaphore?** | Python GIL; for multi-process Celery, Redis broker coordinates task exclusivity. |
| 14 | **Context switch cost?** | Why too many Celery processes on 4-core machine hurts — tune concurrency. |
| 15 | **WSL2 on Windows?** | Docker Desktop runs Linux VM; disk image location affects C: vs D: — you lived this. |

---

## 6. Computer networks — theory + CloudSecure mapping

| # | Question | Solution / CloudSecure tie-in |
|---|----------|-------------------------------|
| 1 | **OSI layers — where is HTTPS?** | TLS (L6), HTTP (L7). Frontend→API `http://localhost:8000` dev; prod terminates TLS at ALB/nginx. |
| 2 | **TCP vs UDP?** | Postgres/Redis/HTTP use **TCP**; reliable delivery matters for findings. |
| 3 | **HTTP methods in your API?** | `GET` findings (safe), `POST` inventory-pull (action, 202), `DELETE` provider. |
| 4 | **REST idempotency?** | `POST inventory-pull` not idempotent — creates new run; `GET` idempotent. |
| 5 | **Status codes you use?** | `202` queued scan, `401` bad token, `409` scan already running / deep scan required, `404` wrong tenant’s provider. |
| 6 | **CORS?** | React on :3000 calls API :8000 — need `Access-Control-Allow-Origin` in dev. |
| 7 | **DNS?** | `neo4j`, `db`, `valkey` Docker DNS; AWS endpoints resolved by boto3. |
| 8 | **Load balancer?** | Scale: multiple FastAPI replicas behind ALB; sticky sessions not needed (stateless JWT/token). |
| 9 | **Connection pooling?** | SQLAlchemy pool to Postgres; Neo4j driver session per request. |
| 10 | **Timeouts?** | OPA `timeout=10`; axios `timeout: 15000` on frontend; prevent hung scans blocking UI. |
| 11 | **TLS handshake?** | Client-server negotiate cipher; cert validates API identity in production. |
| 12 | **WebSockets?** | Not used; UI **polls** `inventory-runs/` every 5s — could upgrade to WS/SSE. |
| 13 | **NAT / private subnets?** | Production: workers in private subnet reach AWS via NAT; no public IPs on tasks. |
| 14 | **STS cross-account?** | **Security token service** — CloudSecure account calls `AssumeRole` into customer account — federated trust, temporary creds. |
| 15 | **HTTP/1.1 vs HTTP/2?** | FastAPI/uvicorn supports HTTP/2 with TLS; multiplexing for many small API calls. |
| 16 | **Reverse proxy?** | nginx forwards `/api` to uvicorn, serves static React build. |
| 17 | **CDN?** | Frontend static assets on CloudFront; API origin separate. |
| 18 | **SYN flood / DDoS?** | Rate limit login; WAF on ALB; out of scope for self-hosted MVP. |
| 19 | **Packet fragmentation?** | Large JSON graph responses — MTU issues rare on localhost; paginate graph API. |
| 20 | **mTLS for microservices?** | Service mesh optional; Compose uses plain HTTP on internal network (isolated bridge). |

---

## 7. Core CS & distributed systems

| # | Topic | CloudSecure application |
|---|--------|-------------------------|
| 1 | **Hashing** | SHA-256 config/tag hashes for delta; consistent compare via sorted JSON keys |
| 2 | **Idempotency** | Re-running scan shouldn’t duplicate findings — upsert on (provider, arn, rule) |
| 3 | **Message queue** | Celery + Redis: decouple API from long scan |
| 4 | **At-least-once delivery** | Celery retries; worker must handle duplicate task attempts |
| 5 | **Backpressure** | `with_backoff` on AWS throttling; single running inventory per provider |
| 6 | **Caching** | Redis schedule hash; could cache OPA results (careful — stale policy) |
| 7 | **Consistent hashing** | If multiple Celery workers, task routing by `queue=inventory` |
| 8 | **Bloom filter** | Could approximate “seen ARNs” — we use exact hash map in Postgres |
| 9 | **Time complexity** | Delta scan O(n) over resources; graph path exponential — limit depth in Cypher |
| 10 | **Space complexity** | Store hashes not full configs in state table |
| 11 | **CAP / eventual consistency** | UI may briefly show old findings until scan completes — eventual |
| 12 | **Leader election** | Single Celery Beat scheduler — avoid duplicate beat in prod (one beat instance) |
| 13 | **Distributed tracing** | Add OpenTelemetry span: API → queue → worker → AWS call |
| 14 | **Security** | Least-privilege IAM role; read-only; no long-lived customer keys in DB |

---

## 8. Project deep-dive Q&A (with solutions)

### 8.1 Architecture & design

**Q1. Walk me through what happens when a user clicks “Scan Now”.**

**Solution:**

1. React `POST /api/v1/providers/{id}/inventory-pull/` with `Authorization: Token …`.
2. FastAPI `inventory_pull()` checks `has_running_inventory_run` → 409 if already running.
3. `perform_inventory_pull_task.delay(tenant_id, provider_id)` enqueues to **inventory** queue → **202**.
4. Celery worker picks task, `create_inventory_run(state='running')`.
5. `run_inventory_pull()`:
   - STS `AssumeRole` into customer account.
   - Resource Explorer `search()` for ARNs (aggregator index).
   - `compute_delta()` vs stored hashes → new/changed/deleted.
   - Optional AWS Config drift ARNs merged into delta.
   - For each changed ARN: fetcher → config dict → OPA evaluate → upsert findings.
   - Update Neo4j inventory nodes.
   - Save hashes; `finalize_inventory_run(completed|partial|failed)`.
6. UI polls `GET .../inventory-runs/` until `state != running`.

---

**Q2. How does multi-tenancy work?**

**Solution:**

- User registers → `create_user_with_tenant()` creates `Tenant` + `UserProfile.tenant_id`.
- Every provider/finding/run row has **`tenant_id`**.
- API never trusts client-sent tenant ID; derives from token → user → profile → `get_current_tenant()`.
- `get_provider_for_tenant(db, pk, tenant.id)` prevents IDOR on provider IDs.

---

**Q3. Why Celery? Why not run scan in FastAPI background task?**

**Solution:**

- Scans run **minutes**, thousands of AWS calls.
- BackgroundTasks share API process — crash/kill API kills scan; no retry; no horizontal scale.
- Celery gives **persistent queue**, retries, separate scaling of workers, Beat for schedule.

---

**Q4. Explain delta scanning.**

**Solution:**

```text
previous = load_hashes(provider_id)   # arn -> {config_hash, tag_hash}
current  = Resource Explorer ARNs + hashes from live tags/config
delta    = { new, changed, deleted }
only fetch full config + evaluate rules for (new ∪ changed)
deleted  -> tombstone in Neo4j, close findings
```

- **Benefit:** Cuts AWS API calls and OPA evaluations on steady state.
- **Hashes:** `compute_config_hash` / `compute_tag_hash` with sorted JSON for stability.

---

**Q5. How does AWS cross-account access work?**

**Solution:**

1. Customer creates IAM role `CloudSecureRole` trusting your account.
2. Platform credentials (`~/.aws` or instance role) call `sts.assume_role(RoleArn=arn:aws:iam::CUSTOMER:role/CloudSecureRole)`.
3. Temporary access key + session token used to create regional boto3 clients.
4. **Least privilege:** read-only actions (Describe*, Get*, Resource Explorer Search).

---

**Q6. What is OPA and how do you use it?**

**Solution:**

- **Open Policy Agent** evaluates **Rego** policies.
- Worker loads `.rego` files into OPA HTTP API (`PUT /v1/policies/...`).
- Per resource: `POST /v1/data/...` with input JSON (config).
- Policies return `deny` messages → persisted as **findings**.
- **Why:** Security team can add rules without shipping new Python; policies are declarative and testable.

---

**Q7. Inventory scan vs deep scan?**

| | Inventory scan | Deep scan |
|---|----------------|-----------|
| **Engine** | Resource Explorer + boto3 | Cartography |
| **Graph** | Simple Resource nodes | Full AWS graph (IAM, SG edges, etc.) |
| **Worker** | `celery` (core image) | `celery-deep-scan` (Cartography image) |
| **Queue** | `inventory` | `deep_scan` |
| **Use** | Compliance findings, dashboard | Attack path, graph visualization |
| **Gate** | Attack engine returns 409 without deep scan `update_tag` |

---

**Q8. How do you prevent concurrent inventory runs?**

**Solution:**

- DB check: `has_running_inventory_run(provider_id)` where `state == 'running'`.
- API returns **409** if user triggers twice.
- Periodic beat skips provider if already running.

---

**Q9. What happens when AWS throttles you?**

**Solution:**

- `with_backoff` / retry on ClientError throttling.
- `stagger_accounts` if multi-account.
- Delta scanning reduces call volume.

---

**Q10. Why did you split FastAPI from Django?**

**Solution:**

- Async-friendly API layer, lighter runtime for read-heavy dashboard.
- **Same Postgres schema** — reuse Django migrations.
- Workers already framework-agnostic; Celery doesn’t need Django.

---

**Q11. How is auth implemented?**

**Solution:**

- Register: bcrypt hash password (`hash_password`).
- Login: verify → `get_or_create_token` → opaque token in `authtoken_token`.
- Requests: `Authorization: Token <key>` → `get_user_by_token`.
- Logout: delete token row.

---

**Q12. Explain attack path analysis.**

**Solution:**

- Requires completed deep scan (`update_tag` in Neo4j).
- Predefined Cypher queries in `worker/jobs/attack_engine/queries.py` (Cartography node labels).
- API runs query, returns paths for UI graph.
- **GDS shortest path:** optional Neo4j Graph Data Science plugin — `gds.shortestPath.dijkstra` for weighted paths.

---

**Q13. How are findings stored and deduplicated?**

**Solution:**

- Finding links: provider, rule name, resource ARN, severity, status (OPEN/SUPPRESSED).
- On re-scan: update existing OPEN finding or create new; resolved when resource passes policy.

---

**Q14. What is Resource Explorer and why aggregator?**

**Solution:**

- AWS service to search resources across regions from one API.
- **Aggregator index** in home region (e.g. `us-east-1`) — required for multi-region discovery; local-only index rejected in code.

---

**Q15. Failure modes you handled?**

**Solution:**

- OPA down → log warning, return empty deny (don’t crash scan).
- Missing fetcher for ARN type → log, skip or infer type from ARN pattern.
- Celery worker crash → `acks_late`, retry task; run marked `failed` on exception.
- Cartography import on wrong image → conditional `CELERY_IMPORT_DEEP_SCAN`.

---

**Q16. How would you scale to 10,000 tenants?**

**Solution:**

- Horizontal Celery workers per queue; rate limit per tenant AWS API.
- Shard Postgres; archive old inventory runs.
- Separate Neo4j cluster per tenant or label-based isolation (`tenant_id` on nodes).
- API rate limits; async-only scans; SQS instead of Redis if needed.

---

**Q17. Security vulnerabilities in your own design?**

**Solution (show maturity):**

- Token in localStorage → XSS risk → httpOnly cookies + CSRF.
- SSRF on OPA URL if misconfigured.
- Tenant IDOR if any endpoint skips `get_provider_for_tenant` — audit all routes.
- Customer IAM role too permissive — document least-privilege policy.

---

**Q18. Why PostgreSQL URL-encode password?**

**Solution:**

- `quote_plus` on password in DB URL when password contains `@` — broke SQLAlchemy connect otherwise.

---

**Q19. What metrics would you add?**

**Solution:**

- Scan duration, resources/sec, OPA eval latency, AWS throttle count, findings by severity, queue depth, task failure rate.

---

**Q20. Explain `CELERY_IMPORT_DEEP_SCAN`.**

**Solution:**

- Main worker must not import `cartography` (not in core requirements).
- Deep-scan container sets env var → `celery_app` imports `worker.jobs.deep_scan.scan` only there.
- Task routed to `deep_scan` queue.

---

### 8.2 AWS & security domain

| # | Question | Short answer |
|---|----------|--------------|
| 1 | What is CSPM? | Continuous cloud config assessment; misconfiguration detection. |
| 2 | CIS Benchmark? | Hardening guidelines; mapped to Rego rules. |
| 3 | IAM role vs user for integration? | **Role** with external trust — no static keys in our DB. |
| 4 | S3 public access finding? | Evaluate bucket policy + Block Public Access via fetcher input to OPA. |
| 5 | IMDSv2? | EC2 metadata service v2 — token required; rule flags IMDSv1. |
| 6 | KMS key rotation? | DescribeKey + policy Rego check. |
| 7 | CloudTrail enabled? | DescribeTrails / GetTrailStatus in fetcher. |
| 8 | Difference SG vs NACL? | SG stateful instance-level; NACL stateless subnet — EC2 rules focus SG. |
| 9 | Privilege escalation in AWS? | IAM policy allows `iam:PassRole` + `sts:AssumeRole` chains — graph finds paths. |
| 10 | Resource Explorer vs Config? | Explorer: discovery; Config: configuration history — we optionally merge Config change signals. |

---

### 8.3 Frontend & API

| # | Question | Answer |
|---|----------|--------|
| 1 | Why React? | Component reuse, ecosystem, Vite fast dev. |
| 2 | State management? | Context (`AuthContext`) + local state; polls inventory runs. |
| 3 | API base URL? | `VITE_API_URL` or hostname:8000. |
| 4 | 202 vs 200 on scan? | Accepted async — body has `task_id`, not final result. |

---

## 9. System design questions

**SD1. Design a CSPM like CloudSecure for AWS + Azure.**

- **Ingestion:** Pluggable connector per cloud (interface `CloudConnector.discover(), .fetch_config()`).
- **Policy:** OPA with shared Rego + cloud-specific packages.
- **Storage:** Postgres metadata; graph DB for relationships; object store for raw snapshots.
- **Compute:** Queue per tenant; fair scheduling; priority for paid tiers.
- **Multi-tenancy:** tenant_id everywhere + optional dedicated DB.

**SD2. Design scan scheduler for 1M accounts.**

- Shard by account ID; priority queue; exponential backoff on throttle; regional workers near AWS region; checkpoint progress in DB; idempotent steps.

**SD3. How to make policy evaluation 10x faster?**

- Evaluate only delta; batch OPA input; compile Rego; cache policy decisions by config hash; parallel worker processes.

---

## 10. Coding / DSA angles from the project

| Problem | Project link |
|---------|--------------|
| **Two-sum / hash map** | ARN → hash map for delta |
| **Graph BFS/DFS** | Attack path = bounded path search in Neo4j |
| **Topological sort** | IAM dependency order (conceptual) |
| **String parsing** | `_arn_to_cfn_type(arn)` |
| **Stable serialize** | `json.dumps(sort_keys=True)` for hashing |
| **Queue design** | Celery FIFO with Redis |
| **Merge intervals** | Config drift time windows |

**Practice:** Implement `compute_delta` on whiteboard given two hash maps.

---

## 11. Behavioral hooks (STAR)

| Theme | Story |
|-------|--------|
| **Debug production issue** | Celery down → cartography import → conditional import + separate worker |
| **Tradeoff** | Full Cartography vs AWS-only image — faster builds, smaller attack surface |
| **Ownership** | End-to-end: IAM setup docs, Windows Docker pitfalls, staged `start-local.ps1` |
| **Learn fast** | Migrated API Django → FastAPI while keeping schema |
| **Collaboration** | Rego policies readable by security reviewers non-dev |

---

## 12. Quick revision checklist

- [ ] Draw architecture from memory (6 boxes + 2 arrows)
- [ ] Explain scan flow in 60 seconds
- [ ] STS AssumeRole trust policy verbally
- [ ] Delta scan + hashing why sorted JSON
- [ ] ACID + tenant isolation query pattern
- [ ] Celery queue names: `inventory`, `deep_scan`
- [ ] OPA request path: load policy → POST data → deny list
- [ ] One failure you fixed (cartography / disk / celery)
- [ ] Scale story: horizontal workers + delta + rate limits
- [ ] Security: IDOR prevention, least privilege IAM

---

## Files to skim before interview

| Path | Why |
|------|-----|
| `backend-fastapi/worker/tasks.py` | Celery entry |
| `backend-fastapi/worker/jobs/inventory/aws.py` | Scan pipeline |
| `backend-fastapi/app/api/deps.py` | Auth + tenant |
| `backend-fastapi/app/api/routers/providers.py` | STS + inventory-pull |
| `backend-fastapi/worker/jobs/rule_engine/opa_client.py` | OPA integration |
| `docker-compose.yml` | Service topology |
| `frontend/src/pages/ScanPage.jsx` | UX → API |

---

*Good luck for 2027 FAANG loops — lead with clarity, tradeoffs, and metrics. This doc is tied to **your** repo; adjust numbers (350+ rules, services) if the codebase changes.*
