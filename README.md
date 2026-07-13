<h1 align="center">
  
  <br>
  CloudSecure
  <br>
  
</h1>

<h4 align="center">Open-source Cloud Security Posture Management (CSPM) for AWS</h4>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11+-green.svg">
  <img alt="Django" src="https://img.shields.io/badge/django-4.x-green.svg">
  <img alt="React" src="https://img.shields.io/badge/react-18-blue.svg">
  <img alt="Docker" src="https://img.shields.io/badge/docker-compose-blue.svg">
  <img alt="OPA" src="https://img.shields.io/badge/OPA-rego-purple.svg">
</p>



---

> **CloudSecure** is an open-source Cloud Security Posture Management (CSPM) platform that continuously scans your AWS environment, detects misconfigurations, maps attack paths, and produces actionable compliance findings — all from a single self-hosted dashboard.



<p align="center">
  <img src="docs/images/hero.png" alt="Custom Rules — Create tenant rules with your own Rego policy" width="900">
</p>

---




## ✨ Features

| Feature | Description |
|---|---|
| **One-click AWS Scan** | Scans S3, EC2, IAM, RDS, KMS, and CloudTrail in under 5 minutes |
| **350+ Security Checks** | CIS Benchmark and India-specific regulatory rules powered by OPA/Rego |
| **Attack Path Analysis** | Neo4j-backed graph engine maps lateral movement and privilege escalation paths |
| **Deep Scan / Graph View** | Interactive node-graph visualization of your entire AWS resource topology |
| **Compliance Reporting** | Exportable reports mapped to CIS, DPDP, RBI, and SBE frameworks |
| **Multi-tenant** | Isolated workspaces per team or customer |
| **Real-time Findings** | Findings appear as resources are scanned — no waiting for full completion |
| **Suppression Workflow** | Mark findings as suppressed to track accepted risk |
| **Delta Scanning** | Incremental scans only re-fetch resources that have changed |
| **IaC Scanning** | Scans the terraform file in the github repo for possible vulnerability. |
| **Intelligent Auditing** | Intelligent remediation steps by the Sarvam AI (India first approach) |


---

## ☁️ Supported AWS Services

| Service | Checks | Standards |
|---|---|---|
| **Amazon S3** | Public access, encryption, versioning, logging, bucket policy | CIS, DPDP, RBI |
| **Amazon EC2** | Security groups, open ports, IMDSv2, public IPs | CIS, SBE |
| **AWS IAM** | MFA, inline policies, role trust policies, access keys | CIS, DPDP |
| **Amazon RDS** | Public access, encryption, backup retention, deletion protection | CIS, RBI |
| **AWS KMS** | Key rotation, key policy, multi-region keys | CIS, DPDP |
| **AWS CloudTrail** | Logging enabled, log validation, CloudWatch integration | CIS, SBE |

---

## 📋 Compliance Frameworks

CloudSecure maps every finding to one or more compliance frameworks:

- **CIS AWS Foundations Benchmark** — Industry-standard hardening guidelines
- **DPDP (Digital Personal Data Protection)** — India's 2023 data protection law
- **RBI Cyber Security Framework** — Reserve Bank of India guidelines for BFSI
- **SBE (SEBI Basic Cyber Hygiene)** — Securities and Exchange Board of India baseline

---

## 🔄 How It Works

<p align="center">
  <img src="docs/images/how-it-works.png" alt="Three Simple Steps: Connect, Scan, Remediate" width="900">
</p>

1. **Connect** — Link your AWS account with a read-only IAM role in under 2 minutes
2. **Scan** — One-click scan across all supported services. Results in seconds
3. **Remediate** — Review findings, follow remediation steps, and export compliance reports

---

## 🖼️ Screenshots

### Security Dashboard
<p align="center">
  <img src="docs/images/dashboard.png" alt="Security Dashboard" width="900">
</p>


The dashboard gives you an at-a-glance view of your security posture:
- **Total Findings** — open issues to address
- **Critical + High** — findings needing immediate attention
- **Resources Scanned** — count across all AWS services
- **Frameworks** — active compliance mappings (CIS, DPDP, RBI, SBE)
- Breakdowns by severity, resource type, and compliance framework

### Add Custom Rules
<p align="center">
  <img src="docs/images/custom-rules.png" alt="CloudSecure — Find & Fix Cloud Misconfigurations Before Attackers Do" width="900">
</p>

### Attack Path Analysis
<p align="center">
  <img src="docs/images/attack-path.png" alt="MITRE Attack Techniques — Attack Path Graph" width="900">
</p>

### IaC Scanning
<p align="center">
  <img src="docs/images/IaC.png" alt="MITRE Attack Techniques — Attack Path Graph" width="900">
</p>

### AI Remediation Guide
<p align="center">
  <img src="docs/images/AI_Remediation.png" alt="MITRE Attack Techniques — Attack Path Graph" width="900">
</p>

 

---

## 🏗️ Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                        Browser                              │
│                React + Vite (port 3000)                     │
└──────────────────────────┬──────────────────────────────────┘
                           │ REST API
┌──────────────────────────▼──────────────────────────────────┐
│                Django / Flask Backend                       │
│      DRF Token Auth · Multi-tenant · REST API               │
└──────┬────────────┬─────────────────┬───────────┬───────────┘
       │            │                 │           │
┌──────▼───┐  ┌─────▼──────┐   ┌──────▼──────┐  ┌─▼───────────┐
│PostgreSQL│  │   Valkey   │   │    Neo4j    │  │  Sarvam AI  │
│  (state) │  │  (broker)  │   │   (graph)   │  │(Remediation)│
└──────────┘  └─────┬──────┘   └─────────────┘  └─────────────┘
                    │
          ┌─────────▼─────────┐           ┌───────────────────┐
          │  Celery Workers   │           │   IaC Scanner     │
          │ inventory · rules │           │ (tfsec / checkov) │
          └─────────┬─────────┘           └─────────▲─────────┘
                    │                               │
          ┌─────────▼──────────┐          ┌─────────┴─────────┐
          │    AWS (boto3)     │          │  GitHub Repos     │
          │   STS AssumeRole   │          │  (Cloned Temp)    │
          └────────────────────┘          └───────────────────┘

```

| Component | Technology | Role |
|---|---|---|
| Frontend | React 18 + Vite + Tailwind | Dashboard UI |
| Backend | Django 4 + Django REST Framework | API server, auth, tenant logic | Flask
| Task Queue | Celery + Valkey | Async inventory pulls and rule evaluation |
| Database | PostgreSQL 15 | Findings, inventory runs, user/tenant data |
| Graph DB | Neo4j 5 | Resource relationship graph, attack paths |
| Policy Engine | OPA (Open Policy Agent) + Rego | Security rule evaluation |
| AWS Integration | boto3 + STS AssumeRole | Read-only AWS resource discovery |

---

## 🚀 Getting Started

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- [AWS CLI](https://aws.amazon.com/cli/) configured with valid credentials (`aws configure`)
- An AWS account where you can create IAM roles

---

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/CloudSecure.git
cd CloudSecure
```

---

### 2. Configure Environment

```bash
cp .env.example .env
```

> See [docs/AURADB.md](docs/AURADB.md) for Neo4j AuraDB setup (recommended). Local Neo4j is optional.

Edit `.env` with your values:

| Variable | Description | Example |
|---|---|---|
| `SECRET_KEY` | Django secret key | `python -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `POSTGRES_DB` | PostgreSQL database name | `cloudsecure` |
| `POSTGRES_USER` | PostgreSQL username | `cloudsecure` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `localpostgres123` |
| `POSTGRES_HOST` | PostgreSQL host (Docker service name) | `db` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |
| `VALKEY_URL` | Valkey/Redis broker URL | `redis://valkey:6379/0` |
| `NEO4J_URI` | Neo4j AuraDB URI (TLS) | `neo4j+s://YOUR_INSTANCE.databases.neo4j.io` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j AuraDB password | _(from Aura console)_ |
| `NEO4J_SHARED_DATABASE` | Aura database name | `neo4j` |
| `DJANGO_SETTINGS_MODULE` | Django settings module | `cloudsecure.settings.local` |
| `AWS_DEFAULT_REGION` | Region where Resource Explorer aggregator is active | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | Leave blank — uses `~/.aws` credentials | _(blank)_ |
| `AWS_SECRET_ACCESS_KEY` | Leave blank — uses `~/.aws` credentials | _(blank)_ |
| `DEBUG` | Django debug mode | `True` |

---

### 3. AWS Setup (One-time)

CloudSecure uses an IAM role with read-only permissions. Run these commands once:

```bash
# Get your AWS Account ID
aws sts get-caller-identity --query Account --output text

# Enable Resource Explorer (required for resource discovery)
aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1

# Verify the index is ACTIVE (may take several minutes to over an hour)
aws resource-explorer-2 get-index --region us-east-1

# Create the CloudSecure IAM role
aws iam create-role \
  --role-name CloudSecureRole \
  --assume-role-policy-document file://trust-policy.json

# Attach read-only permissions
aws iam put-role-policy \
  --role-name CloudSecureRole \
  --policy-name CloudSecurePermissions \
  --policy-document file://permissions-policy.json
```

> `trust-policy.json` and `permissions-policy.json` are included in this repository.

---

### 4. IaC Backend Setup 

```bash
cd IaC_backend
cp .env.example .env
pip install -r requirements.txt  #Download the required packages
python run.py   #To run the development server
```

---

### 5. Build & Start

```bash
make build            # Build Docker images
make up               # Start all services
make migrate          # Run database migrations
make createsuperuser  # Create your admin account
```

---

### 6. Open the App

| Service | URL |
|---|---|
| **Dashboard** | http://localhost:3000 |
| **API** | http://localhost:8000 |
| **IaC Backend** | http://localhost:5000 |
| **Neo4j Aura** | https://console.neo4j.io (or local Browser at http://localhost:7474 with `--profile local-neo4j`) |

1. Log in at http://localhost:3000/login
2. Go to **Connect** → enter your AWS Account ID and role name `CloudSecureRole`
3. Click **Test Connection** — a green check confirms the role works
4. Go to **Scan** → click **Run Scan**
5. Findings will appear in **Findings** as the scan progresses

---

## 🛠️ Useful Commands

| Command | Description |
|---|---|
| `make up` | Start all services |
| `make down` | Stop all services |
| `make build` | Build Docker images |
| `make rebuild` | Rebuild images and restart |
| `make migrate` | Run database migrations |
| `make createsuperuser` | Create an admin user |
| `make logs` | Tail backend + celery logs |
| `make frontend-logs` | Tail frontend logs |
| `make all-logs` | Tail all service logs |
| `make shell` | Open Django shell |

---

## 🔑 Required IAM Permissions

CloudSecure's IAM role requires the following read-only permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "resource-explorer-2:Search",
        "resource-explorer-2:GetIndex",
        "resource-explorer-2:GetDefaultView",
        "resource-explorer-2:ListViews",
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

---

# 🛡️ CloudSecure CLI

CloudSecure is a comprehensive security posture management tool built by **Team Kaali Topi**. It audits Infrastructure as Code (Terraform) to find misconfigurations .

---

## 🚀 cloudSecure-kaalitopi CLI (Python Scanner)

The `cloudsecure-kaalitopi` package is our official CLI tool, allowing you to run security audits directly from your terminal.

---

## Installation Guide 

```bash
pip install cloudsecure-kaalitopi  #This will install the package locally on your system and you can scan the files locally
```

---

## 🛠️ Useful Commands

| Command | Description |
|---|---|
| `cloudsecure-kaalitopi --version` | To know the current verion of the CLI tool. |
| `cloudsecure-kaalitopi iac test.tf` | To scan the file locally , present in the current working directory. |
| `cloudsecure-kaalitopi iac test.tf --csv-export` | To scan as well as save the CSV report locally. |
| `cloudsecure-kaalitopi iac test.tf --pdf-export` | To scan as well as save the PDF report locally. |
| `cloudsecure-kaalitopi --help` | To get more information about the CLI tool. |

---

## 🐛 Troubleshooting

**`NoCredentialError` on connection test**
The backend mounts `~/.aws` from your host. Run `aws configure` on your machine, or set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in `.env`.

**`Resource Explorer index not found`**
Run `aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1` and wait for the index to reach `ACTIVE` state (can take several minutes to over an hour). Verify with `aws resource-explorer-2 get-index --region us-east-1`. Ensure `AWS_DEFAULT_REGION=us-east-1` in your `.env`.

**`Password authentication failed` for PostgreSQL**
The Postgres volume was likely initialized with a different password. Reset it:
```bash
docker compose down -v
docker compose up -d
make migrate
```

```

---

## 🛠️ Useful Commands

| Command | Description |
|---|---|
| `cloudsecure-kaalitopi --version` | To know the current verion of the CLI tool. |
| `cloudsecure-kaalitopi iac test.tf` | To scan the file locally , present in the current working directory. |
| `cloudsecure-kaalitopi iac test.tf --csv-export` | To scan as well as save the CSV report locally. |
| `cloudsecure-kaalitopi iac test.tf --pdf-export` | To scan as well as save the PDF report locally. |
| `cloudsecure-kaalitopi --help` | To get more information about the CLI tool. |

---

## 🐛 Troubleshooting

**`NoCredentialError` on connection test**
The backend mounts `~/.aws` from your host. Run `aws configure` on your machine, or set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in `.env`.

**`Resource Explorer index not found`**
Run `aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1` and wait for the index to reach `ACTIVE` state (can take several minutes to over an hour). Verify with `aws resource-explorer-2 get-index --region us-east-1`. Ensure `AWS_DEFAULT_REGION=us-east-1` in your `.env`.

**`Password authentication failed` for PostgreSQL**
The Postgres volume was likely initialized with a different password. Reset it:
```bash
docker compose down -v
docker compose up -d
make migrate
```

**Neo4j connection refused**
Neo4j takes ~30 seconds to start. Run `make logs` and wait for `Started.` before triggering a scan.

**Celery not picking up tasks**
Check `make logs` — you should see `celery@... ready`. If not, restart with `docker compose restart celery`.

**Findings not appearing after scan**
Ensure OPA is running (`docker compose ps`) and the Rego policies loaded successfully. Check celery logs for `OPA policies loaded`.

**Frontend blank page or CORS errors**
Rebuild the frontend: `docker compose up -d --build frontend`. Check browser console for failing API requests.

## 🐛 Troubleshooting                                                                                                                        
                                         
  > **Before logging in or signing up**, always ensure migrations are run:                                                                     
  > ```bash
  > docker compose exec backend python manage.py migrate                                                                                       
  > ```                                                     

  > **Use `docker compose`** (Docker Compose V2) not `docker-compose` (older V1). If `docker compose` is not found, update Docker Desktop.     
   
  ---                                                                                                                                          
                                                            
  **Findings not appearing after scan**
  This is usually caused by three issues working together:
  1. **OPA unreachable** — Ensure `OPA_URL: http://opa:8181` is set in `docker-compose.yml` for `backend` and `celery`, and `opa` is listed    
  under `depends_on`. Without this, Celery starts before OPA is ready and policy loading fails silently.                                       
  2. **Resource type mappings** — The rule engine must map all Resource Explorer short-form types (`s3:bucket`, `ec2:instance`, `rds:db`,      
  `kms:key`, `cloudtrail:trail`).                                                                                                              
  3. **Delta scan trap** — If a first scan discovered resources but generated no findings (due to the above issues), subsequent scans skip them
   as unchanged. The re-evaluation fallback will automatically force-evaluate any resource with zero findings on the next scan.                
                                                            
  ---                                                                                                                                          
                                                            
  **`NoCredentialError` on connection test**                                                                                                   
  The backend container needs AWS credentials. The `docker-compose.yml` mounts `~/.aws` from your host. Run `aws configure` on your machine
  first, or set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in `.env`.                                                                     
                                                            
  ---                                                                                                                                          
                                                            
  **`Resource Explorer index not found`**
  Run `aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1` and verify with `aws resource-explorer-2 get-index --region
  us-east-1` — wait until `State` is `ACTIVE` (can take several minutes to over an hour). Ensure `AWS_DEFAULT_REGION=us-east-1` in your `.env`.
   
  ---                                                                                                                                          
                                                            
  **`Password authentication failed` for PostgreSQL**                                                                                          
  The Postgres volume was initialized with a different password. Reset it:
  ```bash                                                                                                                                      
  docker compose down -v                                    
  docker compose up -d                                                                                                                         
  docker compose exec backend python manage.py migrate                                                                                         
   
  ---                                                                                                                                          
  Neo4j connection refused                                  
  Neo4j takes ~30 seconds to start. Check logs with docker compose logs neo4j and wait for Started. before triggering a scan.

  ---                                                                                                                                          
  Celery not picking up tasks
  Check logs: docker compose logs -f celery — you should see celery@... ready. If not, restart: docker compose restart celery. Also ensure     
  OPA_URL is set and opa is in depends_on.                  
                                                                                                                                               
  ---                                                       
  Scan stuck in running state                                                                                                                  
  Check Celery worker logs: docker compose logs -f celery. Common causes: AWS rate limiting, missing IAM permissions, or Neo4j not ready.      
  Verify the Resource Explorer index is ACTIVE.
                                                                                                                                               
  ---                                                       
  Frontend blank page or CORS errors                                                                                                           
  Rebuild the frontend: docker compose up -d --build frontend. Check browser console for failing API requests. Ensure                          
  VITE_API_URL=http://localhost:8000 in docker-compose.yml.
                                                                                                                                               
  ---                                                       
  Dashboard shows no data after scan                                                                                                           
  Make sure you have connected a provider, tested the connection successfully, and run at least one scan. If the scan completed but findings   
  are empty, see the Findings not appearing section above.
  ```                               
---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built by <strong>Team Kaalitopi</strong> · Cloud Security Scanner
</p>