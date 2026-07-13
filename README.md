<img width="4320" height="1440" alt="Hackathon Banner" src="https://github.com/user-attachments/assets/c698b2cd-da84-4cb0-9276-125c6a7244aa" />

# 🛡️ CloudSecure

> **Open-source Cloud Security Posture Management (CSPM) platform for AWS that detects misconfigurations, maps attack paths, performs compliance checks, analyzes cloud behavior, and provides AI-powered remediation from a single dashboard.**

<p align="center">

<img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg">
<img alt="Python" src="https://img.shields.io/badge/python-3.11+-green.svg">
<img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-2.x-009688.svg">
<img alt="React" src="https://img.shields.io/badge/React-18-blue.svg">
<img alt="Docker" src="https://img.shields.io/badge/Docker-Compose-blue.svg">
<img alt="OPA" src="https://img.shields.io/badge/OPA-Rego-purple.svg">
<img alt="Neo4j" src="https://img.shields.io/badge/Neo4j-AuraDB-success.svg">

</p>

---

<p align="center">
<img src="docs/images/hero.png" width="1000">
</p>

---

# 📌 Problem & Domain

Cloud infrastructure has become the backbone of modern applications, but securing it remains a major challenge.

Every day, organizations unintentionally expose sensitive cloud resources due to:

- Publicly accessible S3 buckets
- Overly permissive IAM roles
- Misconfigured Security Groups
- Weak encryption policies
- Disabled logging
- Incorrect trust relationships

Traditional cloud security tools are often expensive, closed-source, and difficult for startups, students, SMEs, and research organizations to adopt.

CloudSecure aims to bridge this gap by providing an **open-source Cloud Security Posture Management (CSPM) platform** that continuously scans AWS environments, detects security misconfigurations, visualizes attack paths, analyzes anomalous activities, and generates actionable remediation guidance—all through a self-hosted dashboard.

---

# 🌍 Themes Selected

- ✅ Trust, Identity & Security
- ✅ Developer Tools & Software Infrastructure
  

---

# 🎯 Objective

CloudSecure is designed for:

- Organizations using AWS
- Security teams
- DevSecOps engineers
- Cloud administrators
- Students & researchers
- Startups
- SMEs

### Pain Points

Organizations struggle with:

- Lack of centralized visibility
- Cloud misconfigurations
- Complex compliance requirements
- Manual audits
- Hidden attack paths
- Alert fatigue
- Expensive commercial CSPM solutions

### Our Solution

CloudSecure provides:

- Continuous AWS security assessment
- Automated compliance mapping
- Graph-based attack path analysis
- CloudTrail anomaly detection
- AI-powered remediation suggestions
- Terraform IaC scanning
- Custom security policies using OPA/Rego

---

# 🧠 Team & Approach

## Team Name

**Kaali Topi**

## Team Members

- Ishan Gupta
- Janithashri G
---

## Why We Built CloudSecure

As cloud adoption continues to grow, cloud security has become increasingly complex. Existing enterprise CSPM platforms such as Wiz and Prisma Cloud are powerful but often inaccessible to startups, students, and smaller organizations due to high licensing costs.

Our goal was to build an open-source, modular, and extensible security platform that combines:

- Cloud Security Posture Management
- Graph Security Analytics
- AI-assisted remediation
- Infrastructure-as-Code scanning
- Compliance automation

into one unified dashboard.

---

## Challenges We Solved

- Multi-service AWS inventory collection
- Attack graph generation using Neo4j
- Security policy evaluation using OPA/Rego
- Graph Data Science based risk scoring
- CloudTrail anomaly detection
- AI-generated remediation guidance
- Multi-tenant architecture
- Incremental cloud scanning

---

# 🏗️ System Architecture

<p align="center">

<img src="docs/images/how-it-works.png" width="950">

</p>

## Architecture Components

| Component | Technology | Purpose |
|------------|------------|---------|
| Frontend | React + Vite | Dashboard |
| Backend | FastAPI | REST APIs |
| Database | PostgreSQL | Findings & Users |
| Graph Database | Neo4j AuraDB | Attack Paths |
| Queue | Celery + Valkey | Background Tasks |
| Policy Engine | OPA + Rego | Security Rules |
| Cloud SDK | boto3 | AWS Discovery |
| AI | Sarvam AI | Remediation |
| IaC | tfsec + Checkov | Terraform Scanning |

---

# 🛠 Tech Stack

## Core Technologies

| Layer | Technology |
|---------|------------|
| Frontend | React 18 + Vite + Tailwind CSS |
| Backend | FastAPI |
| Database | PostgreSQL |
| Graph Database | Neo4j AuraDB |
| Background Jobs | Celery |
| Cache | Valkey |
| Security Engine | OPA + Rego |
| Cloud SDK | boto3 |
| IaC Scanner | tfsec + Checkov |
| AI | Sarvam AI |

---

## Additional Technologies Used

- ✅ AI / ML
- ✅ Cyber Security
- ✅ Cloud Computing
- ✅ Graph Databases
- ✅ DevSecOps
- ✅ Docker

---

# 🏆 Sponsored Track

## ✅ Neo4j Track

CloudSecure extensively uses **Neo4j AuraDB** as the graph database powering attack path analysis.

Instead of treating cloud resources independently, every AWS resource is modeled as a graph node while relationships such as trust policies, IAM permissions, network connectivity, and ownership are represented as graph edges.

This enables advanced security analytics including:

- Attack Path Discovery
- Privilege Escalation Detection
- Shadow Resource Identification
- Lateral Movement Analysis
- Critical Asset Prioritization

Graph Data Science algorithms used:

- PageRank
- Betweenness Centrality
- Louvain Community Detection

These analytics dynamically adjust finding severity based on graph context rather than relying solely on static misconfiguration checks.

# ✨ Key Features

CloudSecure combines Cloud Security Posture Management, Graph Security, Compliance Automation, Infrastructure-as-Code Analysis, and AI-powered remediation into a single platform.

---

## ☁️ Cloud Security Posture Management

- ✅ One-click AWS account scanning
- ✅ Resource inventory using AWS Resource Explorer
- ✅ Continuous posture assessment
- ✅ Incremental (Delta) Scanning
- ✅ Real-time findings dashboard
- ✅ Multi-tenant architecture

---

## 🛡️ 350+ Security Checks

CloudSecure evaluates cloud resources against hundreds of security best practices using **OPA + Rego**.

Supported checks include:

- Public S3 buckets
- Bucket encryption
- Versioning
- Bucket logging

- Public EC2 instances
- Open Security Groups
- IMDSv2 enforcement

- IAM MFA
- Trust Policies
- Inline Policies
- Access Keys

- RDS encryption
- Public databases
- Backup retention
- Deletion protection

- KMS rotation
- Key policies

- CloudTrail logging
- Log validation
- CloudWatch integration

---

## 🔥 Attack Path Analysis

CloudSecure builds a graph of cloud resources using **Neo4j AuraDB**.

The platform automatically discovers:

- Privilege Escalation Paths
- Lateral Movement Opportunities
- IAM Trust Relationships
- Resource Dependencies
- Public Exposure Chains

This enables security teams to understand **how individual misconfigurations combine into real attack paths.**

---

## 🧠 Graph Intelligence

CloudSecure goes beyond static security scanning by applying **Graph Data Science algorithms**.

Implemented algorithms include:

- PageRank
- Betweenness Centrality
- Louvain Community Detection

These algorithms identify:

- High-value assets
- Critical IAM roles
- Shadow resources
- Risk propagation
- Graph-based severity escalation

---

## 🤖 AI-Powered Remediation

For high-severity findings, CloudSecure integrates **Sarvam AI** to generate:

- Human-readable explanations
- Step-by-step remediation
- AWS best practices
- Security recommendations

This significantly reduces investigation time for security engineers.

---

## 🏗 Infrastructure as Code (IaC) Scanning

CloudSecure scans Terraform projects using:

- tfsec
- Checkov

Supports:

- Local Terraform directories
- GitHub repositories
- CLI scanning
- PDF reports
- CSV reports

---

## 📈 Compliance Automation

Every finding is automatically mapped to multiple compliance standards.

Supported frameworks:

- CIS AWS Foundations Benchmark
- DPDP (India)
- RBI Cyber Security Framework
- SEBI Basic Cyber Hygiene

Security teams can export compliance reports with a single click.

---

## 📊 CloudTrail Anomaly Detection

CloudSecure analyzes CloudTrail activity to identify unusual behavior.

Features include:

- Behavioral embeddings
- Principal-based anomaly detection
- Entity-level drill-down
- Visual anomaly dashboard

This helps detect suspicious cloud activity that traditional rule-based scanners may miss.

---

## ⚙️ Custom Security Policies

Organizations can write their own security rules using **OPA/Rego**.

Benefits include:

- Tenant-specific policies
- Custom compliance checks
- Internal governance enforcement
- Organization-specific controls

---

## 📸 Dashboard Modules

| Module | Description |
|----------|-------------|
| Dashboard | Overall cloud security posture |
| Scan | Trigger AWS scans |
| Findings | Browse security findings |
| Deep Scan | Full cloud graph ingestion |
| Graph Intel | Graph analytics |
| Rule Effectiveness | Rule performance metrics |
| Anomaly | CloudTrail anomaly detection |
| Providers | AWS account management |
| Reports | Compliance reports |
| Docs | In-app documentation |

---

# ☁️ Supported AWS Services

| AWS Service | Security Checks |
|--------------|----------------|
| Amazon S3 | Encryption, Public Access, Versioning, Logging |
| Amazon EC2 | Security Groups, Public IP, IMDSv2 |
| AWS IAM | MFA, Policies, Trust Relationships |
| Amazon RDS | Encryption, Backups, Public Access |
| AWS KMS | Key Rotation, Policies |
| AWS CloudTrail | Logging, Validation |

---

# 📋 Compliance Frameworks

CloudSecure maps findings against multiple industry standards.

| Framework | Purpose |
|------------|----------|
| CIS AWS Foundations Benchmark | AWS Security Best Practices |
| DPDP | India's Digital Personal Data Protection Act |
| RBI Cyber Security Framework | Banking Security Guidelines |
| SEBI Basic Cyber Hygiene | Securities Compliance |

---

# 🖥️ Platform Walkthrough

CloudSecure provides a unified security dashboard where users can monitor the complete security posture of their AWS environment.

---

## Security Dashboard

<p align="center">
<img src="docs/images/dashboard.png" width="950">
</p>

The dashboard provides:

- Overall Security Score
- Total Findings
- Critical Findings
- Severity Distribution
- Resource Statistics
- Compliance Coverage
- Framework Distribution

---

## Custom Rego Rules

<p align="center">
<img src="docs/images/custom-rules.png" width="950">
</p>

Security teams can create custom Rego policies without modifying application code.

Supported capabilities include:

- Organization-specific policies
- Compliance extensions
- Risk customization
- Tenant isolation

---

## Attack Path Visualization

<p align="center">
<img src="docs/images/attack-path.png" width="950">
</p>

Visualize how attackers could move through cloud resources using graph traversal.

The attack graph highlights:

- Privilege escalation
- IAM trust chains
- Public entry points
- Lateral movement
- Critical assets

---

## Infrastructure-as-Code Scanner

<p align="center">
<img src="docs/images/IaC.png" width="950">
</p>

Scan Terraform files before deployment to identify security issues early in the development lifecycle.

---

## AI Remediation

<p align="center">
<img src="docs/images/AI_Remediation.png" width="950">
</p>

CloudSecure generates contextual remediation guidance using Sarvam AI, allowing engineers to resolve findings much faster.

---

# 📽️ Demo & Deliverables

| Deliverable | Link |
|-------------|------|
| 🎥 Demo Video | https://drive.google.com/drive/folders/1KeWLmW0i2QUEasH9EB4TeS8FCgmjqMVG?usp=drive_link |
| 💻 GitHub Repository | https://github.com/janithashri/cloudsecure-kalitopi |

---

# ✅ Tasks & Bonus Checklist

- [✅] All team members completed the mandatory social task
- [ ] Bonus Task – Badge Sharing
- [ ] Bonus Task – Technical Blog / Article

# 🧪 How to Run the Project

CloudSecure is designed to be deployed locally using Docker and can be connected to any AWS account using a secure read-only IAM role.

---

# 📋 Prerequisites

Before starting, ensure you have:

- Docker Desktop
- Docker Compose
- Python 3.11+
- Node.js 18+
- Git
- AWS CLI
- An AWS Account
- Neo4j AuraDB instance (recommended)

---

# 📂 Clone Repository

```bash
git clone https://github.com/janithashri/cloudsecure-kalitopi.git

cd cloudsecure-kalitopi
```

---

# ⚙️ Configure Environment

Copy the environment template:

```bash
cp .env.example .env
```

Configure the following variables:

| Variable | Description |
|------------|------------|
| SECRET_KEY | FastAPI secret |
| POSTGRES_DB | PostgreSQL database |
| POSTGRES_USER | PostgreSQL username |
| POSTGRES_PASSWORD | PostgreSQL password |
| POSTGRES_HOST | Database host |
| POSTGRES_PORT | Database port |
| VALKEY_URL | Celery broker |
| NEO4J_URI | AuraDB connection |
| NEO4J_USER | Neo4j username |
| NEO4J_PASSWORD | Neo4j password |
| NEO4J_SHARED_DATABASE | Database name |
| AWS_DEFAULT_REGION | AWS region |
| DEBUG | Development mode |

---

# ☁️ AWS Configuration

CloudSecure discovers cloud resources using a dedicated read-only IAM Role.

### Step 1

Configure AWS CLI

```bash
aws configure
```

---

### Step 2

Find your Account ID

```bash
aws sts get-caller-identity --query Account --output text
```

---

### Step 3

Enable AWS Resource Explorer

```bash
aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1
```

Verify:

```bash
aws resource-explorer-2 get-index --region us-east-1
```

Wait until the status becomes:

```
ACTIVE
```

---

### Step 4

Create IAM Role

```bash
aws iam create-role \
--role-name CloudSecureRole \
--assume-role-policy-document file://trust-policy.json
```

---

### Step 5

Attach Permissions

```bash
aws iam put-role-policy \
--role-name CloudSecureRole \
--policy-name CloudSecurePermissions \
--policy-document file://permissions-policy.json
```

The required policy files are already included in this repository.

---

# 🐳 Build Using Docker

Build all services

```bash
docker compose build
```

Start the application

```bash
docker compose up -d
```

---

## Optional Services

### Deep Scan Worker

```bash
docker compose --profile deep-scan up -d celery-deep-scan
```

---

### Local Neo4j

Instead of AuraDB

```bash
docker compose --profile local-neo4j up -d neo4j
```

---

### Initialize Anomaly Tables

```bash
docker compose exec backend python scripts/init_anomaly_tables.py
```

---

# 🏃 Start IaC Backend

```bash
cd IaC_backend

cp .env.example .env

pip install -r requirements.txt

python run.py
```

---

# 🌐 Access the Platform

| Service | URL |
|------------|------|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| IaC Backend | http://localhost:5000 |
| Neo4j Aura Console | https://console.neo4j.io |

---

# 🚀 Getting Started

1. Register a new account.

2. Login.

3. Open **Connect Providers**

4. Enter:

- AWS Account ID
- Role Name

```
CloudSecureRole
```

5. Test Connection.

6. Run Scan.

7. Open Findings.

8. Explore:

- Graph Intel
- Deep Scan
- AI Remediation
- Compliance Reports
- Anomaly Detection

---

# 💻 CloudSecure CLI

CloudSecure also provides a standalone CLI for Infrastructure-as-Code scanning.

---

## Installation

```bash
pip install cloudsecure-kaalitopi
```

---

## CLI Commands

Check version

```bash
cloudsecure-kaalitopi --version
```

---

Scan Terraform

```bash
cloudsecure-kaalitopi iac main.tf
```

---

Generate CSV Report

```bash
cloudsecure-kaalitopi iac main.tf --csv-export
```

---

Generate PDF Report

```bash
cloudsecure-kaalitopi iac main.tf --pdf-export
```

---

Help

```bash
cloudsecure-kaalitopi --help
```

---

# 🔑 Required AWS Permissions

CloudSecure requires read-only permissions for:

- Resource Explorer
- Amazon S3
- Amazon EC2
- IAM
- Amazon RDS
- AWS KMS
- CloudTrail
- STS

The repository already contains:

```
permissions-policy.json

trust-policy.json
```

These policies grant only the minimum permissions required for posture assessment.

---

# 🛠 Useful Docker Commands

Start services

```bash
docker compose up -d
```

Stop services

```bash
docker compose down
```

---

Rebuild

```bash
docker compose build
```

---

Restart Backend

```bash
docker compose restart backend celery
```

---

View Logs

```bash
docker compose logs -f backend celery
```

---

Deep Scan Worker

```bash
docker compose --profile deep-scan up -d celery-deep-scan
```

---

Windows Helper

```powershell
.\scripts\start-local.ps1
```

---

Security Scan Before Push

```powershell
.\scripts\prepare-public-push.ps1
```

---

# 🐛 Troubleshooting

## AWS Credentials Missing

Error:

```
NoCredentialError
```

Solution:

```bash
aws configure
```

or configure credentials inside `.env`.

---

## Resource Explorer Not Found

Create an Aggregator Index

```bash
aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1
```

---

## PostgreSQL Authentication Failed

Recreate volumes

```bash
docker compose down -v

docker compose up -d
```

---

## Findings Not Appearing

Check OPA

```bash
docker compose ps opa
```

Check Celery

```bash
docker compose logs -f celery
```

---

## Celery Tasks Not Running

Restart workers

```bash
docker compose restart celery
```

---

## Frontend Blank Screen

Rebuild frontend

```bash
docker compose up -d --build frontend
```

---

## Neo4j Connection Error

Verify:

- AuraDB URI
- Username
- Password
- Database Name

---

## Graph Intelligence Disabled

Graph Data Science requires:

- Neo4j Aura Professional

or

- Local Neo4j with GDS plugin enabled.

---

# 📂 Project Structure

```text
cloudsecure-kalitopi/
│
├── frontend/
├── backend-fastapi/
├── backend/
├── IaC_backend/
├── docs/
├── scripts/
├── docker/
├── rules/
├── workers/
├── graph/
├── docker-compose.yml
├── README.md
└── LICENSE
```

# 🚀 Roadmap & Future Scope

CloudSecure is designed as a modular security platform and will continue evolving beyond AWS posture management.

## 🌩 Multi-Cloud Support

We plan to extend support to:

- Microsoft Azure
- Google Cloud Platform (GCP)
- Oracle Cloud Infrastructure (OCI)
- Alibaba Cloud

allowing organizations to manage security across hybrid and multi-cloud environments.

---

## ☸️ Kubernetes Security

Upcoming Kubernetes features include:

- Cluster posture assessment
- RBAC analysis
- Network Policy validation
- Pod Security Standards
- Kubernetes attack path analysis

---

## 🔄 Continuous Monitoring

Instead of scheduled scans, CloudSecure will support:

- Event-driven scanning
- AWS EventBridge integration
- Real-time alerts
- Continuous compliance monitoring

---

## 🤖 AI Security Copilot

Future AI capabilities include:

- Natural language querying of findings
- Automated investigation workflows
- Root cause analysis
- Remediation prioritization
- Security report generation
- Risk summarization for executives

---

## 🛡 Auto Remediation

Future releases aim to support:

- One-click remediation
- Safe rollback mechanisms
- Terraform patch generation
- Automated IAM policy correction
- Security Group hardening

---

## 📊 Advanced Analytics

Planned analytics include:

- Risk scoring dashboards
- Organization-wide security score
- Compliance trend analysis
- Historical posture comparison
- Executive reporting

---

## 🔔 Notifications

Future integrations:

- Slack
- Microsoft Teams
- Discord
- Email Alerts
- PagerDuty
- Jira
- ServiceNow

---

## 📱 Mobile Dashboard

A lightweight mobile application will provide:

- Live findings
- Critical alerts
- Compliance status
- AI remediation summaries

---

# 🤝 Contributing

We welcome contributions from the open-source community.

Whether you're interested in cloud security, backend development, frontend engineering, graph databases, or DevSecOps, we'd love your help.

## How to Contribute

1. Fork the repository

```bash
git clone https://github.com/janithashri/cloudsecure-kalitopi.git
```

2. Create a feature branch

```bash
git checkout -b feature/my-feature
```

3. Commit your changes

```bash
git commit -m "Add awesome feature"
```

4. Push to your fork

```bash
git push origin feature/my-feature
```

5. Open a Pull Request 🚀

Please open an issue before implementing major changes so we can discuss the proposed design.

---

# 📎 Resources & Credits

CloudSecure builds upon several outstanding open-source technologies.

## Cloud

- AWS
- boto3
- AWS Resource Explorer

---

## Backend

- FastAPI
- SQLAlchemy
- Pydantic
- Celery
- Valkey

---

## Frontend

- React
- Vite
- Tailwind CSS

---

## Graph & Analytics

- Neo4j AuraDB
- Neo4j Graph Data Science
- Cartography

---

## Security

- Open Policy Agent (OPA)
- Rego
- tfsec
- Checkov

---

## Artificial Intelligence

- Sarvam AI

---

## Infrastructure

- Docker
- Docker Compose

---

We sincerely thank the maintainers of these open-source projects for making CloudSecure possible.

---

# 🏆 Why CloudSecure?

Unlike traditional CSPM tools that focus only on misconfiguration detection, CloudSecure combines multiple security capabilities into a single unified platform.

✅ Cloud Security Posture Management

✅ Attack Path Analysis

✅ Graph Intelligence

✅ AI Remediation

✅ Infrastructure-as-Code Scanning

✅ Compliance Automation

✅ CloudTrail Anomaly Detection

✅ Custom Security Policies

✅ Multi-Tenant Architecture

This enables security teams to identify not only **what is vulnerable**, but also **what actually matters most** based on graph context and attack paths.

---

# 🌟 Highlights

- 🔍 350+ Security Rules
- ☁️ AWS Cloud Inventory
- 🧠 Graph Data Science
- 🤖 AI-powered Remediation
- 🛡 OPA/Rego Policy Engine
- 📊 Compliance Reporting
- 🏗 Terraform Security Scanner
- 📈 Attack Path Visualization
- ⚡ FastAPI Backend
- ⚛ React Dashboard
- 🐳 Docker Deployment
- 🌐 Fully Open Source

---

# 📜 License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for complete details.

---

# ❤️ Our Hackathon Journey

CloudSecure began as an ambitious idea to make enterprise-grade cloud security accessible to everyone.

Throughout this hackathon, we tackled challenges spanning cloud inventory collection, graph databases, policy evaluation, anomaly detection, AI integration, compliance automation, and scalable system design. Building a platform that could seamlessly connect these diverse components while remaining modular and open source was both demanding and incredibly rewarding.

The experience strengthened our understanding of cloud security, distributed systems, and collaborative engineering, while reinforcing our belief that advanced security tooling should be available to organizations of every size—not just large enterprises.

This project represents not just a hackathon submission, but the foundation of an extensible open-source Cloud Security Posture Management platform that we hope to continue improving with the community.

---

# ⭐ Support the Project

If you found CloudSecure useful, please consider:

⭐ Starring the repository

🍴 Forking the project

🐛 Reporting issues

💡 Suggesting new features

🤝 Contributing code

Every contribution helps make cloud security more accessible for everyone.

---

<p align="center">

## 🛡️ Built with ❤️ by Team Kaali Topi

**Open Source • Cloud Security • DevSecOps • Graph Intelligence • AI**

Thank you for checking out **CloudSecure**!

⭐ **If you like this project, don't forget to give it a star!** ⭐

</p>
