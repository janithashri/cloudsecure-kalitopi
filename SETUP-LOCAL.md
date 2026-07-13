# CloudSecure — Local Setup (Windows, PowerShell)

Project root: `C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\`  
Docker is already installed; this guide skips Docker checks.

---

## Step 1 — Environment file

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure
copy .env.example .env
```

Edit `.env` and fill every value as below.

| Variable | Exact value or how to get it |
|----------|-----------------------------|
| **SECRET_KEY** | Generate with Python. Run this in PowerShell, then paste the output into `.env`: `python -c "import secrets; print(secrets.token_urlsafe(50))"` |
| **POSTGRES_PASSWORD** | Safe local value, e.g. `localpostgres123` |
| **NEO4J_URI** | Neo4j AuraDB URI from [console.neo4j.io](https://console.neo4j.io), e.g. `neo4j+s://xxx.databases.neo4j.io`. For local Neo4j use `bolt://neo4j:7687` with `--profile local-neo4j`. |
| **NEO4J_USER** | `neo4j` |
| **NEO4J_PASSWORD** | Password from Aura console (shown once at instance creation), or your local Neo4j password |
| **DEBUG** | `True` |
| **POSTGRES_DB** | `cloudsecure` |
| **POSTGRES_USER** | `cloudsecure` |
| **POSTGRES_HOST** | `db` (Docker service name) |
| **POSTGRES_PORT** | `5432` |
| **VALKEY_URL** | `redis://valkey:6379/0` |
| **NEO4J_SHARED_DATABASE** | `neo4j` |
| **DJANGO_SETTINGS_MODULE** | `cloudsecure.settings.local` |
| **AWS_DEFAULT_REGION** | `us-east-1` (Resource Explorer aggregator is in this region) |
| **AWS_ACCESS_KEY_ID** | Leave **blank** — you will use `~/.aws` credentials |
| **AWS_SECRET_ACCESS_KEY** | Leave **blank** — you will use `~/.aws` credentials |
| **DJANGO_SUPERUSER_EMAIL** | Optional for local; leave blank if you will run `createsuperuser` manually |
| **DJANGO_SUPERUSER_PASSWORD** | Optional; leave blank if using `createsuperuser` |

**Example `.env` (minimal for local):**

```env
SECRET_KEY=<paste output of python -c "import secrets; print(secrets.token_urlsafe(50))">
DEBUG=True
POSTGRES_DB=cloudsecure
POSTGRES_USER=cloudsecure
POSTGRES_PASSWORD=localpostgres123
POSTGRES_HOST=db
POSTGRES_PORT=5432
VALKEY_URL=redis://valkey:6379/0
NEO4J_URI=neo4j+s://YOUR_INSTANCE.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=
NEO4J_SHARED_DATABASE=neo4j
DJANGO_SETTINGS_MODULE=cloudsecure.settings.local
DJANGO_SUPERUSER_EMAIL=
DJANGO_SUPERUSER_PASSWORD=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
```

---

## Step 2 — AWS credentials

**Check if credentials are already configured:**

```powershell
aws sts get-caller-identity
```

**Success** — you see JSON with `UserId`, `Account`, `Arn`. You are good.

**If it fails** (e.g. "Unable to locate credentials"):

1. **Configure credentials:**
   ```powershell
   aws configure
   ```
2. **What each prompt expects:**
   - **AWS Access Key ID:** Your IAM user access key (e.g. `AKIA...`).
   - **AWS Secret Access Key:** The secret for that key.
   - **Default region name:** `us-east-1` (or your preferred region; app uses `us-east-1` for Resource Explorer).
   - **Default output format:** `json`.

3. **Where to find Access Key ID and Secret in AWS Console:**
   - Sign in to AWS Console → **IAM** → **Users** → your user → **Security credentials** tab → **Access keys** → **Create access key**. Copy **Access key ID** and **Secret access key** (secret is shown only once).

4. **Verify after configuring:**
   ```powershell
   aws sts get-caller-identity
   ```
   You should see your account ID and ARN.

---

## Step 3 — AWS Resource Explorer setup (one-time)

**Create the aggregator index:**

```powershell
aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1
```

- **Console first?** You do **not** need to enable Resource Explorer in the console first; this CLI command creates the index. If your account has never used Resource Explorer, the first `create-index` enables it.
- **If you get permission errors:** Ensure your IAM user/role has `resource-explorer-2:CreateIndex` (and later `GetIndex`, `Search`). The CloudSecure IAM role (Step 4) gets these for the *assumed* role; your **default** credentials need permission to create the index once in the account.

**Verify the index exists:**

```powershell
aws resource-explorer-2 get-index --region us-east-1
```

- **Still indexing:** Response includes `"State": "CREATING"` or `"State": "UPDATING"`. Wait and run again.
- **Ready:** Response includes `"State": "ACTIVE"` and an `"Arn"` for the index.
- **How long:** Indexing can take **several minutes to over an hour** depending on how many resources and regions you have. Poll every few minutes with `get-index` until `State` is `ACTIVE`.

**Example ready response:**

```json
{
    "Arn": "arn:aws:resource-explorer-2:us-east-1:123456789012:index/...",
    "State": "ACTIVE",
    "Type": "AGGREGATOR"
}
```

---

## Step 4 — IAM role creation (CLI only)

### 4a. Get your account ID

```powershell
aws sts get-caller-identity --query Account --output text
```

Note the 12-digit account ID (e.g. `123456789012`). Use it wherever you see `YOUR_ACCOUNT_ID` below.

### 4b. Create the trust policy file

Create `trust-policy.json` in a folder of your choice (e.g. project root). Replace `YOUR_ACCOUNT_ID` with the value from 4a.

**trust-policy.json:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### 4c. Create the role

From the directory where `trust-policy.json` is (e.g. project root):

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure
aws iam create-role --role-name CloudSecureRole --assume-role-policy-document file://trust-policy.json
```

Expected: JSON with `Role` containing `RoleName`, `Arn`, `AssumeRolePolicyDocument`.

### 4d. Create the permission policy file

Create `permissions-policy.json` in the same directory.

**permissions-policy.json:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "resource-explorer-2:Search",
        "resource-explorer-2:GetIndex",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetPublicAccessBlock",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "iam:GetRole",
        "iam:GetUser",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListMFADevices",
        "rds:DescribeDBInstances",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### 4e. Attach the policy to the role

```powershell
aws iam put-role-policy --role-name CloudSecureRole --policy-name CloudSecurePermissions --policy-document file://permissions-policy.json
```

No output means success.

### 4f. Verify role and policy

```powershell
aws iam get-role --role-name CloudSecureRole
```

Check: `Role.AssumeRolePolicyDocument` has one statement with `Action: "sts:AssumeRole"` and `Principal.AWS` = `arn:aws:iam::YOUR_ACCOUNT_ID:root`.

```powershell
aws iam get-role-policy --role-name CloudSecureRole --policy-name CloudSecurePermissions
```

Check: `PolicyDocument.Statement[0].Action` contains all the listed actions (resource-explorer-2, s3, ec2, iam, rds, kms, cloudtrail, sts).

### 4g. Test assume-role

Replace `YOUR_ACCOUNT_ID` with your account ID:

```powershell
aws sts assume-role --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/CloudSecureRole --role-session-name TestSession
```

- **Success:** JSON with `Credentials` containing `AccessKeyId`, `SecretAccessKey`, `SessionToken`, and `Expiration`. No error.
- **Failure (e.g. AccessDenied):** Usually trust policy: principal not allowed to assume the role, or role name/ARN wrong. Re-check 4b and that you substituted the correct account ID.

---

## Step 5 — Start the app

**Windows:** If Docker Desktop shows *"Turning off the Docker Engine..."* when you run CloudSecure, the app is not shutting Docker down — the engine is **crashing** (usually **C: disk almost full** or **not enough RAM**). Free **at least 5–10 GB on C:**, then in Docker Desktop → **Settings → Resources** set **Memory** to **6 GB** (if your PC has 16 GB RAM). Wait until Docker says **Running** before starting containers.

**Recommended (staged, lighter):**

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure
docker compose build backend celery celery-beat frontend
.\scripts\start-local.ps1
```

**All-in-one (heavier — can kill Docker on low RAM/disk):**

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure
docker compose build
docker compose up -d
```

Deep-scan worker is **off by default** (large image). Enable only when needed:

```powershell
docker compose --profile deep-scan build celery-deep-scan
docker compose --profile deep-scan up -d celery-deep-scan
```

**Log output to confirm each service:**

- **PostgreSQL ready:** In `docker compose logs db` you see something like "database system is ready to accept connections".
- **Neo4j ready:** Takes ~30s. In `docker compose logs neo4j` you see "Remote interface available at http://localhost:7474" or "Started".
- **Django dev server:** In `docker compose logs backend` you see "Starting development server at http://0.0.0.0:8000/" and "Quit the server with CTRL-BREAK".
- **Celery worker:** In `docker compose logs celery` you see "celery@... ready" and "Connected to redis://...".
- **Celery Beat:** In `docker compose logs celery-beat` you see "beat: Starting..." and "Scheduler: DatabaseScheduler".
- **Frontend Vite:** In `docker compose logs frontend` you see "VITE ready" and "Local: http://localhost:3000/".

**Check all containers are running:**

```powershell
docker compose ps
```

All services (db, valkey, neo4j, backend, celery, celery-beat, frontend) should show state **Up**.

---

## Step 6 — Run migrations and create login

```powershell
docker compose exec backend python manage.py migrate
```

Expected: "Applying ... OK" for each migration.

```powershell
docker compose exec backend python manage.py createsuperuser
```

Prompts (and what to enter):

- **Username:** Login username (e.g. `admin`).
- **Email address:** Your email (e.g. `admin@example.com`); can be left blank if your project allows it.
- **Password:** Your chosen password (typed once).
- **Password (again):** Same password.

Use the **username** and **password** you enter here to log into the app at http://localhost:3000/login.

---

## Step 7 — First login and connecting AWS account

1. Open **http://localhost:3000/login**.
2. Enter the **username** and **password** you set in `createsuperuser`. Submit.
3. After login you should be on the dashboard. Navigate to **Connect AWS Account** (or the equivalent link in the UI).
4. Fill the form:
   - **Provider Name:** Any label (e.g. `My AWS Account`).
   - **AWS Account ID:** Your 12-digit account ID (same as Step 4a: `aws sts get-caller-identity --query Account --output text`).
   - **IAM Role Name:** `CloudSecureRole`.
5. Click **Test Connection.** A **green success** means the app assumed the role and (if applicable) checked Resource Explorer; you can proceed.
6. Click **Save.**

---

## Step 8 — Trigger first scan and verify

### From the UI

- Go to **Dashboard** and click **Trigger Manual Scan** (or the button that starts a scan for the connected provider).
- Watch for: status changing to “running” then “completed” or a success message. Errors may appear in the UI or in Celery logs.

### From PowerShell (direct API)

Get a token using your superuser **username** and **password**:

```powershell
# Get token (use the username and password from createsuperuser)
$body = @{ username = "admin"; password = "yourpassword" } | ConvertTo-Json
$login = Invoke-RestMethod -Uri "http://localhost:8000/api/auth/login/" -Method POST -Body $body -ContentType "application/json"
$token = $login.token
$headers = @{ Authorization = "Token $token" }

# List providers
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/providers/" -Headers $headers

# Trigger scan (replace 1 with your provider id from the list)
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/providers/1/inventory-pull/" -Method POST -Headers $headers
```

### Watch Celery logs

```powershell
docker compose logs -f celery
```

- **Scan running:** Log lines about "inventory", "pull", "run_scan", or task received for the inventory job.
- **Completed:** Task finished with "succeeded" or no error and a log indicating completion.
- **Failed:** Exception or "failed" in logs; check traceback (e.g. assume role, Resource Explorer, Neo4j connection).

### Verify graph data (Aura or local Neo4j)

**Aura:** Open [Neo4j Aura Console](https://console.neo4j.io) → your instance → **Query** (or use Neo4j Browser from the console).

**Local Neo4j** (`docker compose --profile local-neo4j up -d neo4j`):

1. Open **http://localhost:7474**.
2. Login: **neo4j** / your `NEO4J_PASSWORD` from `.env`.
3. Run:

```cypher
MATCH (r:Resource)-[:BELONGS_TO]->(a:AWSAccount)
RETURN r.type, r.status, count(r) AS total
ORDER BY total DESC
```

**Successful result:** You see rows with `r.type` (e.g. AWS resource types), `r.status`, and `total` counts. Non-empty result means resources were written to the graph. Empty result can mean: scan not run yet, scan failed, or no resources in the account.

---

## Step 9 — Troubleshooting (5 common failures)

### 1. AssumeRole failed — trust policy issue

- **Error:** AccessDenied or "is not authorized to perform: sts:AssumeRole" when testing connection or running scan.
- **Cause:** Trust policy does not allow your principal (e.g. IAM user or role) to assume `CloudSecureRole`. Common: wrong account ID in trust policy, or principal restricted to a specific user/role.
- **Fix:** Ensure `trust-policy.json` has `Principal.AWS` = `arn:aws:iam::YOUR_ACCOUNT_ID:root` (account ID from `aws sts get-caller-identity --query Account --output text`). Update the role:
  ```powershell
  aws iam update-assume-role-policy --role-name CloudSecureRole --policy-document file://trust-policy.json
  ```
  Then test again with `aws sts assume-role ...`.

### 2. Resource Explorer returns empty — index not ready or wrong region

- **Error:** Scan runs but finds no resources, or error like "Resource Explorer index not found" / "index is LOCAL not AGGREGATOR".
- **Cause:** Index not created, still in CREATING/UPDATING, or app is using wrong region (must be `us-east-1` for aggregator).
- **Fix:** Run `aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1`. Then:
  ```powershell
  aws resource-explorer-2 get-index --region us-east-1
  ```
  Wait until `State` is `ACTIVE`. Ensure `AWS_DEFAULT_REGION` or the code path that calls Resource Explorer uses `us-east-1`.

### 3. Neo4j graph empty after scan — writer not connecting

- **Error:** Celery task “succeeds” but Neo4j has no `Resource` nodes (or no `BELONGS_TO` to `AWSAccount`).
- **Cause:** Neo4j writer cannot connect: wrong `NEO4J_URI`, `NEO4J_USER`, or `NEO4J_PASSWORD` in `.env`; or Neo4j not ready when worker started.
- **Fix:** Check `.env`: `NEO4J_URI` must be your Aura URI (`neo4j+s://...`) or `bolt://neo4j:7687` for local profile. Restart backend and Celery: `docker compose restart backend celery`. See [docs/AURADB.md](docs/AURADB.md).

### 4. Celery not picking up the task — queue mismatch

- **Error:** You trigger a scan (UI or API) but nothing happens in Celery logs; task never runs.
- **Cause:** Task is sent to a queue that the worker is not consuming (e.g. task routed to `inventory` but worker only listens to `default`, or opposite).
- **Fix:** In `docker-compose.yml` the Celery command is `-Q default,inventory`. Ensure the code that sends the inventory task uses the same queue (e.g. `inventory`). If your task is routed to another queue, add it to `-Q` or change the task’s queue to `default` or `inventory`. Restart: `docker compose restart celery`.

### 0. Docker Desktop — "Turning off the Docker Engine..." when starting CloudSecure

- **What you see:** Docker UI says engine is turning off (or pausing) right after `docker compose up` or `docker compose build`.
- **Cause:** CloudSecure does **not** call Docker shutdown. The Linux VM exits because **disk is full** (especially **C:**) or **out of memory** (Neo4j + Postgres + several Celery processes on a ~4 GB Docker limit).
- **Fix (in order):**
  1. Free space on **C:** (Settings → Storage). You need several GB free even if the Docker disk image is on **D:**.
  2. Docker Desktop → **Settings → Resources** → **Memory** → **6 GB** (or more) → **Apply & Restart**. Wait until **Running**.
  3. Use staged startup: `.\scripts\start-local.ps1` (do **not** build `celery-deep-scan` on first run).
  4. Avoid `docker compose down` between tests if you only need a quick stop — use `docker compose stop` so the engine stays warm.
  5. Confirm: `docker info` shows **Server** without errors before `compose up`.

### 5. Frontend shows blank page — VITE_API_URL wrong or CORS error

- **Error:** http://localhost:3000 loads a blank page, or browser console shows CORS or failed requests to the API.
- **Cause:** Frontend is calling the wrong API URL (e.g. wrong host/port), or backend is not allowing the frontend origin in CORS.
- **Fix:** In `docker-compose.yml`, frontend has `VITE_API_URL: http://localhost:8000`. Rebuild so the env is picked up: `docker compose up -d --build frontend`. In browser dev tools (F12) check Network: API requests must go to `http://localhost:8000`. If CORS errors appear, ensure Django CORS settings (e.g. `CORS_ALLOWED_ORIGINS` or `CORS_ALLOW_ALL_ORIGINS` in dev) include `http://localhost:3000`.

---

## Step 10 — Enable AWS Config drift detection (optional but recommended)

Resource Explorer is good for discovery (`new/deleted/tag changes`) but may miss pure config drift.
CloudSecure can augment delta selection with AWS Config change signals.

### 10a) Environment flags

In `.env`:

```env
ENABLE_AWS_CONFIG_DRIFT=true
AWS_CONFIG_REGION=ap-south-1
AWS_CONFIG_INITIAL_LOOKBACK_MINUTES=180
```

- `ENABLE_AWS_CONFIG_DRIFT=true`: turns on AWS Config signal enrichment.
- `AWS_CONFIG_REGION`: region where your AWS Config recorder/aggregator is active.
- `AWS_CONFIG_INITIAL_LOOKBACK_MINUTES`: first-run lookback window for warm start.

### 10b) IAM permissions (CloudSecureRole)

Add these actions to the role policy used by inventory:

```json
"config:SelectResourceConfig",
"config:DescribeConfigurationRecorderStatus"
```

### 10c) Validate access from CloudSecure backend

Run:

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\backend
.\venv\Scripts\Activate.ps1
python manage.py validate_aws_config_access --provider-id 1 --region ap-south-1
```

Expected success:
- `AWS Config reachable. Recorders: [...]`

### 10d) End-to-end behavior check

1. Restart backend + celery worker after changing `.env`.
2. Trigger inventory pull from UI.
3. Check latest run `stats`:
   - `config_changed_signals` should be non-zero when AWS Config reports changed resources.
   - `delta_count` should include those signals.
4. Confirm changed resource findings/config are refreshed even when tags were untouched.

If `config_changed_signals` stays `0`, verify:
- AWS Config recorder is enabled in target account/region.
- role has `config:*` actions above.
- `AWS_CONFIG_REGION` matches recorder region.

---

**End of setup guide.** For project-specific API paths or auth format, refer to the backend’s URL config and the frontend’s `AuthContext` / login flow.
