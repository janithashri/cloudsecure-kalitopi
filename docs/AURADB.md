# Neo4j AuraDB setup

CloudSecure uses **Neo4j AuraDB** for the graph database (attack paths, deep scan, graph intelligence). Local Docker Neo4j is optional for offline development.

## 1. Create an Aura instance

1. Sign in at [Neo4j Aura](https://neo4j.com/cloud/aura/).
2. Create a new **AuraDB Free** (or Professional for GDS deep-scan analytics).
3. Save the generated password — it is shown only once.
4. Copy the connection URI, e.g. `neo4j+s://YOUR_INSTANCE_ID.databases.neo4j.io`.

## 2. Configure `.env`

```env
NEO4J_URI=neo4j+s://YOUR_INSTANCE_ID.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=your-aura-password
NEO4J_SHARED_DATABASE=neo4j
```

Restart API and workers after changing `.env`:

```powershell
docker compose restart backend celery celery-deep-scan
```

## 3. Verify connectivity

From the backend container:

```powershell
docker compose exec backend python -c "
from worker.jobs.inventory.neo4j_writer import get_neo4j_driver
from app.core.config import get_settings
s = get_settings()
d = get_neo4j_driver()
with d.session(database=s.neo4j_shared_database) as sess:
    print(sess.run('RETURN 1 AS ok').single())
"
```

## Graph Data Science (GDS)

Deep scan graph analytics (PageRank, betweenness, shadow risk) require the **GDS plugin**:

| Deployment | GDS support |
|---|---|
| AuraDB Professional | Yes (managed) |
| AuraDB Free | Limited — graph intelligence may show `gds_available: false` |
| Local Neo4j (`docker compose --profile local-neo4j up -d neo4j`) | Yes with `NEO4J_PLUGINS: graph-data-science` |

## Optional: local Neo4j instead of Aura

```powershell
docker compose --profile local-neo4j up -d neo4j
```

Then in `.env`:

```env
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your-local-password
```

Browse at http://localhost:7474.
