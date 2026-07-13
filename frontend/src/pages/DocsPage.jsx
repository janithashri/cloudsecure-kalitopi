import { useState } from "react";
import { Link } from "react-router-dom";

const sections = [
  {
    id: "overview",
    title: "Overview",
    content: (
      <>
        <p>
          CloudSecure is an open-source <strong>Cloud Security Posture Management (CSPM)</strong> platform
          that continuously scans your AWS environment, detects misconfigurations, maps attack paths,
          and produces actionable compliance findings — all from a single self-hosted dashboard.
        </p>
        <p className="mt-3">
          It scans 6 AWS services, evaluates resources against Rego policy files powered by OPA,
          and maps findings to 4 compliance frameworks with actionable remediation guidance for every issue.
        </p>
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { val: "350+", label: "Security Checks" },
            { val: "6", label: "AWS Services" },
            { val: "4", label: "Frameworks" },
            { val: "<5min", label: "First Scan" },
          ].map((s) => (
            <div key={s.label} className="rounded-lg border border-slate-700 bg-slate-800/50 p-3 text-center">
              <p className="text-xl font-bold text-emerald-400">{s.val}</p>
              <p className="text-xs text-slate-400">{s.label}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "architecture",
    title: "Architecture",
    content: (
      <>
        <p>CloudSecure uses a modern, event-driven microservices architecture:</p>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Component</th>
                <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Technology</th>
                <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Purpose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {[
                ["Frontend", "React 18 + Vite + TailwindCSS", "Dashboard, findings, reports UI"],
                ["Backend API", "Django 4 + DRF", "REST API, authentication, tenant isolation"],
                ["Task Queue", "Celery + Valkey (Redis)", "Async inventory pulls and rule evaluation"],
                ["Policy Engine", "OPA (Open Policy Agent)", "Rego-based rule evaluation"],
                ["Primary DB", "PostgreSQL 15", "Users, providers, findings, resource configs"],
                ["Graph DB", "Neo4j 5", "Resource relationship mapping and attack paths"],
                ["Cloud SDK", "boto3 (AWS SDK)", "AWS API calls via STS AssumeRole"],
              ].map(([comp, tech, purpose]) => (
                <tr key={comp}>
                  <td className="px-3 py-2 font-medium text-emerald-400">{comp}</td>
                  <td className="px-3 py-2 text-slate-300">{tech}</td>
                  <td className="px-3 py-2 text-slate-400">{purpose}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-6 rounded-xl border border-slate-700 bg-slate-900 p-5 font-mono text-xs leading-relaxed text-slate-400">
          <p className="mb-2 text-sm font-semibold text-emerald-400">Scan Workflow</p>
          <p>1. User triggers scan → POST /api/v1/providers/&lt;id&gt;/inventory-pull/</p>
          <p>2. Celery task queued → perform_inventory_pull_task</p>
          <p>3. AssumeRole into target AWS account via STS</p>
          <p>4. Query Resource Explorer + fetch detailed configs via boto3</p>
          <p>5. Hash resource state for delta change detection</p>
          <p>6. Store in PostgreSQL (ResourceConfig) + Neo4j (graph)</p>
          <p>7. For each resource: build OPA input → evaluate Rego rules</p>
          <p>8. Create/update Finding records with severity + remediation</p>
          <p>9. Re-evaluate any resource with zero findings (recovery fallback)</p>
          <p>10. Frontend polls for completion → displays results</p>
        </div>
      </>
    ),
  },
  {
    id: "services",
    title: "Supported AWS Services",
    content: (
      <div className="grid gap-3 sm:grid-cols-2">
        {[
          { name: "Amazon S3", checks: "Public access blocks, encryption, versioning, logging, bucket policies, ACLs, cross-account access" },
          { name: "Amazon EC2", checks: "Security groups, open ports, IMDSv2, public IPs, instance profile, VPC membership" },
          { name: "AWS IAM", checks: "MFA enforcement, inline policies, role trust policies, unused access keys, overly permissive roles" },
          { name: "Amazon RDS", checks: "Encryption at rest, public accessibility, backup retention, deletion protection, multi-AZ" },
          { name: "AWS KMS", checks: "Key rotation, key policies, key manager, multi-region keys" },
          { name: "AWS CloudTrail", checks: "Multi-region logging, log file validation, CloudWatch integration, S3 delivery, KMS encryption" },
        ].map((svc) => (
          <div key={svc.name} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
            <h4 className="font-semibold text-white">{svc.name}</h4>
            <p className="mt-1 text-xs text-slate-400">{svc.checks}</p>
          </div>
        ))}
      </div>
    ),
  },
  {
    id: "frameworks",
    title: "Compliance Frameworks",
    content: (
      <>
        <p>CloudSecure maps every finding to one or more compliance frameworks:</p>
        <div className="mt-4 space-y-3">
          {[
            {
              name: "CIS AWS Foundations Benchmark",
              tag: "CIS",
              desc: "Industry-standard security configuration guidelines from the Center for Internet Security. Covers identity, logging, monitoring, and networking controls.",
            },
            {
              name: "India DPDP Act 2023",
              tag: "DPDP",
              desc: "Digital Personal Data Protection Act compliance. Focuses on data encryption, access controls, and data handling requirements for organizations processing Indian citizens' data.",
            },
            {
              name: "RBI Cyber Security Framework",
              tag: "RBI",
              desc: "Reserve Bank of India cybersecurity framework for financial institutions. Covers data protection, access management, and infrastructure security requirements.",
            },
            {
              name: "SBE / SEBI Cyber Hygiene",
              tag: "SBE",
              desc: "SEBI Basic Cyber Hygiene and CERT-In advisory compliance. Covers vulnerability management, logging, encryption, and incident response readiness.",
            },
          ].map((fw) => (
            <div key={fw.tag} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <div className="flex items-center gap-2">
                <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs font-bold text-emerald-400">{fw.tag}</span>
                <h4 className="font-semibold text-white">{fw.name}</h4>
              </div>
              <p className="mt-2 text-sm text-slate-400">{fw.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "quickstart",
    title: "Quick Start Guide",
    content: (
      <div className="space-y-4">
        <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
          <h4 className="flex items-center gap-2 font-semibold text-white">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500 text-xs font-bold text-white">1</span>
            Prerequisites
          </h4>
          <ul className="mt-2 space-y-1 text-sm text-slate-400">
            <li>— Docker Desktop installed and running</li>
            <li>— AWS CLI configured on your host (<code className="rounded bg-slate-700 px-1 text-emerald-400">aws configure</code>)</li>
            <li>— An AWS account where you can create IAM roles</li>
          </ul>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
          <h4 className="flex items-center gap-2 font-semibold text-white">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500 text-xs font-bold text-white">2</span>
            Clone & Configure
          </h4>
          <pre className="mt-2 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-slate-300">
            {`git clone <repo-url>
cd cloud-secure-kaalitopi
cp .env.example .env
# Edit .env with the values below`}
          </pre>
          <p className="mt-3 text-xs font-semibold text-slate-400">Required .env variables:</p>
          <div className="mt-2 overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="px-2 py-1.5 text-left text-slate-500">Variable</th>
                  <th className="px-2 py-1.5 text-left text-slate-500">Example</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {[
                  ["SECRET_KEY", "python -c \"import secrets; print(secrets.token_urlsafe(50))\""],
                  ["POSTGRES_DB", "cloudsecure"],
                  ["POSTGRES_USER", "cloudsecure"],
                  ["POSTGRES_PASSWORD", "localpostgres123"],
                  ["POSTGRES_HOST", "db"],
                  ["POSTGRES_PORT", "5432"],
                  ["VALKEY_URL", "redis://valkey:6379/0"],
                  ["NEO4J_URI", "neo4j+s://YOUR_INSTANCE.databases.neo4j.io"],
                  ["NEO4J_USER", "neo4j"],
                  ["NEO4J_PASSWORD", "(from Neo4j Aura console)"],
                  ["NEO4J_SHARED_DATABASE", "neo4j"],
                  ["DJANGO_SETTINGS_MODULE", "cloudsecure.settings.local"],
                  ["AWS_DEFAULT_REGION", "us-east-1"],
                  ["DEBUG", "True"],
                ].map(([k, v]) => (
                  <tr key={k}>
                    <td className="px-2 py-1.5 font-mono text-emerald-400">{k}</td>
                    <td className="px-2 py-1.5 text-slate-400">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
          <h4 className="flex items-center gap-2 font-semibold text-white">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500 text-xs font-bold text-white">3</span>
            Start the App
          </h4>
          <pre className="mt-2 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-slate-300">
            {`docker compose up -d --build
docker compose exec backend python manage.py migrate
docker compose exec backend python manage.py createsuperuser`}
          </pre>
          <p className="mt-2 text-xs text-slate-400">Open <span className="text-emerald-400">http://localhost:3000</span> and sign in with the superuser credentials.</p>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
          <h4 className="flex items-center gap-2 font-semibold text-white">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500 text-xs font-bold text-white">4</span>
            AWS IAM Role Setup
          </h4>
          <pre className="mt-2 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-slate-300">
            {`# Get your Account ID
aws sts get-caller-identity --query Account --output text

# Enable Resource Explorer (must be us-east-1)
aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1

# Verify index is ACTIVE (may take several minutes to over an hour)
aws resource-explorer-2 get-index --region us-east-1

# Create the IAM role
aws iam create-role \\
  --role-name CloudSecureRole \\
  --assume-role-policy-document file://trust-policy.json

# Attach permissions
aws iam put-role-policy \\
  --role-name CloudSecureRole \\
  --policy-name CloudSecurePermissions \\
  --policy-document file://permissions-policy.json`}
          </pre>
          <details className="mt-3">
            <summary className="cursor-pointer text-sm text-emerald-400 hover:text-emerald-300">
              View required IAM permissions
            </summary>
            <pre className="mt-2 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-slate-300">
              {`{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "resource-explorer-2:Search",
      "resource-explorer-2:GetIndex",
      "resource-explorer-2:GetDefaultView",
      "resource-explorer-2:ListViews",
      "s3:GetBucketPolicy", "s3:GetBucketAcl",
      "s3:GetBucketEncryption", "s3:GetBucketVersioning",
      "s3:GetBucketLogging", "s3:GetPublicAccessBlock",
      "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
      "iam:GetRole", "iam:GetUser",
      "iam:ListRolePolicies", "iam:GetRolePolicy",
      "iam:ListUserPolicies", "iam:GetUserPolicy",
      "iam:ListMFADevices",
      "rds:DescribeDBInstances",
      "kms:DescribeKey", "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:GetEventSelectors",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}`}
            </pre>
          </details>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
          <h4 className="flex items-center gap-2 font-semibold text-white">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500 text-xs font-bold text-white">5</span>
            Run Your First Scan
          </h4>
          <ol className="mt-2 space-y-1 text-sm text-slate-400">
            <li>1. Go to <strong className="text-white">Connect</strong> → enter your AWS Account ID and role name <code className="rounded bg-slate-700 px-1 text-emerald-400">CloudSecureRole</code></li>
            <li>2. Click <strong className="text-white">Test Connection</strong> — green check means the role works</li>
            <li>3. Go to <strong className="text-white">Scan</strong> → click <strong className="text-white">Scan Now</strong></li>
            <li>4. View results in <strong className="text-white">Dashboard</strong> and <strong className="text-white">Findings</strong></li>
            <li>5. Export compliance reports from <strong className="text-white">Reports</strong></li>
          </ol>
        </div>
      </div>
    ),
  },
  {
    id: "dashboard",
    title: "Dashboard",
    content: (
      <>
        <p>
          The <strong>Dashboard</strong> is the home screen after login. It gives you an at-a-glance view of your entire AWS security posture across all connected accounts.
        </p>
        <div className="mt-4 space-y-3">
          {[
            {
              title: "Summary Cards",
              desc: "Four metric cards at the top show: Total Findings (all open issues), Critical + High (findings needing immediate attention), Resources Scanned (total AWS resources discovered across all services), and Frameworks (number of active compliance mappings — CIS, DPDP, RBI, SBE).",
            },
            {
              title: "Severity Breakdown Chart",
              desc: "A visual chart breaks down findings by severity — Critical, High, Medium, Low. Use this to prioritize remediation effort. Critical and High findings represent the most exploitable misconfigurations.",
            },
            {
              title: "Resource Type Breakdown",
              desc: "Shows which AWS service has the most findings (S3, EC2, IAM, RDS, KMS, CloudTrail). Helps identify which service area needs the most attention.",
            },
            {
              title: "Compliance Framework Coverage",
              desc: "Maps your findings across CIS, DPDP, RBI, and SBE frameworks so you can see compliance gaps at a glance.",
            },
            {
              title: "Recent Findings List",
              desc: "A live list of the most recent findings from the last scan, showing severity badge, rule name, affected resource ARN, and timestamp.",
            },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <h4 className="font-semibold text-white">{item.title}</h4>
              <p className="mt-1 text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "scan",
    title: "Scan",
    content: (
      <>
        <p>
          The <strong>Scan</strong> tab is where you trigger security scans against your connected AWS account. CloudSecure uses AWS Resource Explorer to discover resources and then fetches detailed configuration for each one via boto3.
        </p>
        <div className="mt-4 space-y-3">
          {[
            {
              title: "Selecting a Provider",
              desc: "Choose which connected AWS account (provider) to scan from the dropdown. You must have at least one provider connected and tested before scanning.",
            },
            {
              title: "Triggering a Scan",
              desc: "Click 'Scan Now' to start an async inventory pull. The scan runs in the background via a Celery worker — you can navigate away and come back. The scan discovers resources across S3, EC2, IAM, RDS, KMS, CloudTrail, and Security Groups.",
            },
            {
              title: "Scan Progress & Status",
              desc: "The scan status updates in real time: Queued → Running → Completed (or Failed). Stats shown include total resources discovered, new/changed/deleted resources, and new findings created.",
            },
            {
              title: "Scan History",
              desc: "All previous scan runs are listed with their timestamp, status, and stats. Use this to track how your security posture changes over time between scans.",
            },
            {
              title: "Delta Scanning",
              desc: "CloudSecure only re-evaluates resources that have changed since the last scan (new, modified tags, or config drift). This keeps scans fast. Any resource that currently has zero findings is always re-evaluated as a safety fallback.",
            },
            {
              title: "Services Scanned",
              desc: "Each scan card shows what is checked per service: S3 (public access, encryption, versioning, logging), EC2 (security groups, IMDSv2, public IPs), IAM (MFA, inline policies, key rotation), RDS (encryption, public access, backup), KMS (rotation, policy), CloudTrail (logging, validation, CloudWatch).",
            },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <h4 className="font-semibold text-white">{item.title}</h4>
              <p className="mt-1 text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "findings",
    title: "Findings",
    content: (
      <>
        <p>
          The <strong>Findings</strong> tab is the main workspace for reviewing and managing security issues discovered during scans. Every misconfiguration found is recorded as a finding with full context.
        </p>
        <div className="mt-4 space-y-3">
          {[
            {
              title: "Filtering Findings",
              desc: "Filter by severity (Critical, High, Medium, Low), status (Open, Suppressed), compliance framework (CIS, DPDP, RBI, SBE), and resource type. Combine filters to focus on what matters most — e.g. Critical + CIS + IAM.",
            },
            {
              title: "Finding Detail",
              desc: "Click any finding to expand it. Each finding shows: the rule ID and name, affected resource ARN, AWS region, account ID, severity, compliance frameworks it maps to, and step-by-step remediation instructions.",
            },
            {
              title: "Suppressing Findings",
              desc: "If a finding is a known accepted risk (e.g. a public S3 bucket intentionally used for a static website), you can suppress it. Suppressed findings are tracked but excluded from your active count. They are never overwritten by subsequent scans.",
            },
            {
              title: "Custom Rules (Rego Editor)",
              desc: "Write your own Rego policies to create custom security rules specific to your organisation. Set a rule name, rule ID, target resource type (e.g. AWS::S3::Bucket), severity, compliance frameworks, and paste your Rego policy. Custom rules run alongside the built-in CIS/DPDP/RBI/SBE rules on every scan.",
            },
            {
              title: "Remediation Steps",
              desc: "Every finding includes actionable remediation steps. Follow these to fix the misconfiguration directly in AWS. After fixing and re-scanning, the finding will no longer appear if the issue is resolved.",
            },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <h4 className="font-semibold text-white">{item.title}</h4>
              <p className="mt-1 text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "providers",
    title: "Providers",
    content: (
      <>
        <p>
          The <strong>Providers</strong> tab lists all AWS accounts connected to CloudSecure. Each provider represents one AWS account that CloudSecure can scan.
        </p>
        <div className="mt-4 space-y-3">
          {[
            {
              title: "Provider Card",
              desc: "Each connected account shows as a card with: the provider name you gave it, the AWS Account ID, the IAM role name used for scanning, connection status, and the date it was added.",
            },
            {
              title: "Test Connection",
              desc: "Use the 'Test Connection' button to verify CloudSecure can still assume the IAM role in the target account. A green check means the role is reachable and Resource Explorer is accessible. A failure here will also cause scans to fail.",
            },
            {
              title: "Removing a Provider",
              desc: "Delete a provider to disconnect an AWS account. This removes the provider record but does not delete findings already collected. Use this if you've rotated role names or decommissioned an account.",
            },
            {
              title: "Multi-tenant Isolation",
              desc: "Each user account (tenant) only sees their own providers and findings. Providers are fully isolated between tenants — you cannot access another user's connected accounts.",
            },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <h4 className="font-semibold text-white">{item.title}</h4>
              <p className="mt-1 text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "connect",
    title: "Connect",
    content: (
      <>
        <p>
          The <strong>Connect</strong> tab is where you onboard a new AWS account into CloudSecure by providing the account details and IAM role.
        </p>
        <div className="mt-4 space-y-3">
          {[
            {
              title: "Provider Name",
              desc: "A friendly label for this AWS account (e.g. 'Production' or 'Dev Account'). This is only used for display within CloudSecure.",
            },
            {
              title: "AWS Account ID",
              desc: "The 12-digit AWS Account ID of the account you want to scan. Get it by running: aws sts get-caller-identity --query Account --output text",
            },
            {
              title: "IAM Role Name",
              desc: "The name of the IAM role CloudSecure will assume in the target account. Default is CloudSecureRole. This role must have the required read-only permissions and a trust policy that allows your CloudSecure account to assume it.",
            },
            {
              title: "Test Connection",
              desc: "Before saving, click 'Test Connection'. CloudSecure will attempt to assume the role via STS and verify Resource Explorer is accessible. A green success message confirms everything is configured correctly. Common failures: wrong account ID, role doesn't exist, trust policy is misconfigured, or Resource Explorer index is not ACTIVE.",
            },
            {
              title: "IAM Setup Guide",
              desc: "The Connect page includes an inline guide with the exact CLI commands and JSON policies needed to create the CloudSecureRole in the target account. Follow this if you haven't set up the role yet. The trust policy must reference your CloudSecure host account ID as the Principal.",
            },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <h4 className="font-semibold text-white">{item.title}</h4>
              <p className="mt-1 text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "deepscan",
    title: "Deep Scan & Attack Path",
    content: (
      <>
        <p>
          The <strong>Deep Scan</strong> tab provides attack path analysis powered by Neo4j and mapped to the <strong>MITRE ATT&CK framework</strong>. It goes beyond individual misconfigurations to show how an attacker could chain multiple weaknesses together to move laterally or escalate privileges.
        </p>
        <div className="mt-4 space-y-3">
          {[
            {
              title: "MITRE ATT&CK Panel",
              desc: "The left panel lists attack techniques grouped by tactic (Initial Access, Privilege Escalation, Lateral Movement, etc.). Each technique shows whether your environment has violations — red indicates active attack paths found, green means no violations for that technique.",
            },
            {
              title: "Running Attack Analysis",
              desc: "Click 'Run Attack Analysis' to execute all MITRE ATT&CK queries against your Neo4j resource graph. The engine checks for real attack paths based on your actual resource relationships — not just individual misconfigs. Examples: Public EC2 with Admin IAM Role, Publicly Reachable Data Plane with Missing Encryption, S3 Bucket with Sensitive Tag Indicators.",
            },
            {
              title: "Graph Visualization",
              desc: "The right panel renders an interactive force-directed graph of your AWS resource topology. Nodes represent AWS resources (EC2 instances, IAM roles, S3 buckets, security groups, etc.) and edges show relationships between them. Attack paths are highlighted in red with dashed edges so you can visually trace the exploit chain.",
            },
            {
              title: "Interacting with the Graph",
              desc: "Zoom and pan to explore large environments. Drag nodes to rearrange the layout. Search by node name, ARN, or resource type to filter the graph. Toggle edge labels to see relationship types. The graph supports up to 300 nodes for large AWS environments.",
            },
            {
              title: "Attack Path Detail",
              desc: "Click a MITRE technique to see the specific attack query, which nodes are violated, the MITRE tactic/technique mapping, a description of the attack scenario, and remediation guidance to break the attack path.",
            },
            {
              title: "Filter by Node Type",
              desc: "Use the node type filter (top of the graph) to focus on specific resource types — e.g. show only EC2 and IAM nodes to investigate privilege escalation paths.",
            },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <h4 className="font-semibold text-white">{item.title}</h4>
              <p className="mt-1 text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "reports",
    title: "Reports",
    content: (
      <>
        <p>
          The <strong>Reports</strong> tab lets you generate and export compliance reports based on your current findings. Reports can be shared with auditors, management, or used for internal compliance tracking.
        </p>
        <div className="mt-4 space-y-3">
          {[
            {
              title: "Framework Filter",
              desc: "Filter the report by compliance framework — CIS, DPDP, RBI, or SBE. You can generate a focused report for a specific regulatory requirement rather than exporting all findings at once.",
            },
            {
              title: "Severity Filter",
              desc: "Narrow the report to specific severity levels (Critical, High, Medium, Low). For executive summaries, export Critical + High only. For full audit reports, include all severities.",
            },
            {
              title: "PDF Export",
              desc: "Generates a formatted PDF report with a cover header, summary table (total findings by severity), and a detailed findings table with rule name, resource ARN, severity, compliance framework, and remediation steps. Suitable for audit submissions.",
            },
            {
              title: "CSV Export",
              desc: "Exports findings as a CSV file with all fields — rule ID, rule name, ARN, region, account ID, severity, status, compliance frameworks, and remediation steps. Use this for importing into spreadsheets, ticketing systems, or SIEM tools.",
            },
            {
              title: "Findings Preview",
              desc: "Before exporting, the Reports page shows a preview of findings that will be included based on your current filters, so you can verify the scope before generating the report.",
            },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <h4 className="font-semibold text-white">{item.title}</h4>
              <p className="mt-1 text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "iac",
    title: "IaC Scanning",
    content: (
      <>
        <p>
          The <strong>IaC (Infrastructure-as-Code) Scanner</strong> scans Terraform repositories for security misconfigurations before they are deployed to AWS. It catches issues at the code level — before they become live vulnerabilities.
        </p>
        <div className="mt-4 space-y-3">
          {[
            {
              title: "How It Works",
              desc: "Provide a GitHub repository URL containing Terraform code. CloudSecure fetches the repository and runs static analysis against the Terraform files, identifying insecure resource configurations such as open security groups, unencrypted storage, public S3 buckets, and missing IAM conditions.",
            },
            {
              title: "Vulnerability Cards",
              desc: "Each detected issue is shown as a card with: severity badge (Critical, High, Medium, Low), the resource and attribute affected, a description of the vulnerability, and the file/line location in your Terraform code.",
            },
            {
              title: "Summary Statistics",
              desc: "At the top of results, a summary shows total vulnerabilities found broken down by severity — Critical, High, Medium, Low. Use this to gauge the overall risk posture of your infrastructure code before deploying.",
            },
            {
              title: "AI Suggested Remediation",
              desc: "Where available, each vulnerability card includes an AI-generated remediation suggestion specific to the issue found. This gives you a concrete code fix to apply to your Terraform, not just a generic description of the problem.",
            },
            {
              title: "Export Results",
              desc: "IaC scan results can be exported as PDF or CSV for sharing with the development team or including in pull request reviews and security sign-off workflows.",
            },
            {
              title: "Shift Left Security",
              desc: "IaC scanning is a 'shift left' approach — catching misconfigurations in code review rather than after deployment. Use it as part of your CI/CD pipeline to prevent insecure infrastructure from ever reaching production.",
            },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <h4 className="font-semibold text-white">{item.title}</h4>
              <p className="mt-1 text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "ai-remediation",
    title: "AI Remediation Guide",
    content: (
      <>
        <p>
          CloudSecure includes AI-assisted remediation to help you fix security findings faster. Rather than just telling you what is wrong, the AI guide tells you exactly how to fix it in your specific environment.
        </p>
        <div className="mt-4 space-y-3">
          {[
            {
              title: "Per-Finding Remediation Steps",
              desc: "Every finding in the Findings tab includes detailed remediation steps generated for that specific rule and resource type. These steps are specific — for example, an S3 public access finding will include the exact AWS CLI command or Console steps to enable Block Public Access for that bucket.",
            },
            {
              title: "IaC AI Fix Suggestions",
              desc: "In the IaC Scanner, findings marked with the AI badge include a suggested Terraform code fix. The AI analyses the vulnerable resource block and suggests the corrected HCL configuration — for example, adding encryption = true to an aws_s3_bucket_server_side_encryption_configuration block.",
            },
            {
              title: "Attack Path Remediation",
              desc: "In the Deep Scan tab, each MITRE ATT&CK technique violation includes a remediation guide explaining how to break the specific attack chain. For example, for a 'Public EC2 with Admin IAM Role' finding, the guide explains both how to remove the public IP and how to scope down the IAM role permissions.",
            },
            {
              title: "Custom Rule Guidance",
              desc: "When writing custom Rego rules in the Findings tab, you can include your own remediation text in the rule description. This text is then shown to users alongside any violations the custom rule generates, giving your team organisation-specific remediation guidance.",
            },
            {
              title: "Prioritisation Guidance",
              desc: "Critical and High severity findings are always surfaced first. The AI remediation steps for these findings prioritise the fastest path to reducing risk — typically a single AWS Console change or CLI command that eliminates the most dangerous exposure.",
            },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
              <h4 className="font-semibold text-white">{item.title}</h4>
              <p className="mt-1 text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    id: "commands",
    title: "Useful Commands",
    content: (
      <div className="space-y-4">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Command</th>
                <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {[
                ["docker compose up -d --build", "Build images and start all services"],
                ["docker compose up -d", "Start all services (no rebuild)"],
                ["docker compose down", "Stop all services"],
                ["docker compose down -v", "Stop all services and delete volumes"],
                ["docker compose restart backend", "Restart only the backend"],
                ["docker compose restart celery", "Restart only the Celery worker"],
                ["docker compose restart frontend", "Restart only the frontend"],
                ["docker compose exec backend python manage.py migrate", "Run database migrations"],
                ["docker compose exec backend python manage.py createsuperuser", "Create an admin user"],
                ["docker compose logs -f backend", "Tail backend logs"],
                ["docker compose logs -f celery", "Tail Celery worker logs"],
                ["docker compose logs -f", "Tail all service logs"],
                ["docker compose ps", "Show status of all containers"],
                ["docker compose exec backend python manage.py shell", "Open Django shell"],
              ].map(([cmd, desc]) => (
                <tr key={cmd}>
                  <td className="px-3 py-2 font-mono text-xs text-emerald-400">{cmd}</td>
                  <td className="px-3 py-2 text-slate-400">{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    ),
  },
  {
    id: "api",
    title: "API Reference",
    content: (
      <>
        <p>CloudSecure exposes a RESTful API. All endpoints require <code className="rounded bg-slate-700 px-1 text-emerald-400">Authorization: Token &lt;token&gt;</code> unless marked public.</p>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Method</th>
                <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Endpoint</th>
                <th className="px-3 py-2 text-left text-xs font-medium uppercase text-slate-500">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {[
                ["POST", "/api/auth/register/", "Create new account (public)"],
                ["POST", "/api/auth/login/", "Login, returns token (public)"],
                ["POST", "/api/auth/logout/", "Invalidate token"],
                ["GET", "/api/auth/me/", "Current user info"],
                ["GET", "/api/v1/providers/", "List connected AWS providers"],
                ["POST", "/api/v1/providers/", "Add new AWS provider"],
                ["POST", "/api/v1/providers/:id/test-connection/", "Test AWS IAM role connection"],
                ["POST", "/api/v1/providers/:id/inventory-pull/", "Trigger async scan"],
                ["GET", "/api/v1/providers/:id/inventory-runs/", "List scan runs"],
                ["GET", "/api/v1/providers/:id/findings/", "List findings (filterable by severity, status, type)"],
                ["GET", "/api/v1/providers/:id/findings/summary/", "Findings summary by severity/framework"],
                ["PATCH", "/api/v1/findings/:id/suppress/", "Suppress a finding"],
                ["GET", "/api/v1/providers/:id/graph/", "Neo4j graph data (nodes + edges)"],
              ].map(([method, path, desc]) => (
                <tr key={path}>
                  <td className="px-3 py-2">
                    <span
                      className={`rounded px-1.5 py-0.5 text-xs font-bold ${method === "GET"
                          ? "bg-blue-500/10 text-blue-400"
                          : method === "POST"
                            ? "bg-emerald-500/10 text-emerald-400"
                            : "bg-yellow-500/10 text-yellow-400"
                        }`}
                    >
                      {method}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-300">{path}</td>
                  <td className="px-3 py-2 text-slate-400">{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </>
    ),
  },
  {
    id: "troubleshooting",
    title: "Troubleshooting",
    content: (
      <div className="space-y-3">
        {[
          {
            q: "Findings not appearing after scan",
            a: "This is usually caused by three issues working together. (1) OPA unreachable: ensure OPA_URL: http://opa:8181 is set in docker-compose.yml for backend and celery, and opa is listed under depends_on. Without this, Celery starts before OPA is ready and policy loading fails silently. (2) Resource type mappings: the rule engine must map all Resource Explorer short-form types (s3:bucket, ec2:instance, rds:db, kms:key, cloudtrail:trail). (3) Delta scan trap: if a first scan discovered resources but generated no findings, subsequent scans skip them as unchanged. The re-evaluation fallback will automatically force-evaluate any resource with zero findings on the next scan.",
          },
          {
            q: "NoCredentialError on test-connection",
            a: "The backend container needs AWS credentials. The docker-compose.yml mounts ~/.aws from your host into the container. Run aws configure on your machine first, or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your .env file.",
          },
          {
            q: "Resource Explorer index not found",
            a: "Run: aws resource-explorer-2 create-index --type AGGREGATOR --region us-east-1. Then verify with: aws resource-explorer-2 get-index --region us-east-1 — wait until State is ACTIVE (can take several minutes to over an hour). Ensure AWS_DEFAULT_REGION=us-east-1 in your .env.",
          },
          {
            q: "Password authentication failed for PostgreSQL",
            a: "The Postgres volume was initialized with a different password. Reset it: docker compose down -v && docker compose up -d && docker compose exec backend python manage.py migrate",
          },
          {
            q: "Neo4j connection refused",
            a: "Neo4j takes ~30 seconds to start. Check logs with: docker compose logs neo4j — wait for the 'Started.' message before triggering a scan.",
          },
          {
            q: "Celery not picking up tasks",
            a: "Check logs: docker compose logs -f celery. You should see 'celery@... ready'. If not, restart: docker compose restart celery. Also ensure OPA_URL is set and opa is in depends_on.",
          },
          {
            q: "Scan stuck in running state",
            a: "Check Celery worker logs: docker compose logs -f celery. Common causes: AWS rate limiting, missing IAM permissions, or Neo4j not ready. Also verify the Resource Explorer index is ACTIVE.",
          },
          {
            q: "Frontend blank page or CORS errors",
            a: "Rebuild the frontend: docker compose up -d --build frontend. Check browser console for failing API requests. Ensure VITE_API_URL=http://localhost:8000 in docker-compose.yml.",
          },
          {
            q: "Dashboard shows no data after scan",
            a: "Make sure you have connected a provider, tested the connection successfully, and run at least one scan. If the scan completed but findings are empty, see the 'Findings not appearing' entry above.",
          },
        ].map((item) => (
          <div key={item.q} className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
            <h4 className="font-semibold text-white">{item.q}</h4>
            <p className="mt-1 text-sm text-slate-400">{item.a}</p>
          </div>
        ))}
      </div>
    ),
  },
];

export default function DocsPage() {
  const [activeSection, setActiveSection] = useState("overview");

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      {/* Navbar */}
      <nav className="sticky top-0 z-50 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
          <Link to="/" className="flex items-center gap-2">
            <img src="/logo.png" alt="CloudSecure" className="h-9 w-9 object-contain" />
            <span className="text-xl font-bold">CloudSecure</span>
          </Link>
          <div className="flex items-center gap-4">
            <Link to="/" className="text-sm text-slate-400 hover:text-white">Home</Link>
            <Link
              to="/login"
              className="rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-white hover:bg-emerald-400"
            >
              Launch App
            </Link>
          </div>
        </div>
      </nav>

      <div className="mx-auto flex max-w-7xl gap-8 px-6 py-10">
        {/* Sidebar nav */}
        <aside className="hidden w-56 shrink-0 lg:block">
          <div className="sticky top-24 space-y-1">
            <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Documentation</p>
            {sections.map((s) => (
              <button
                key={s.id}
                onClick={() => {
                  setActiveSection(s.id);
                  document.getElementById(s.id)?.scrollIntoView({ behavior: "smooth" });
                }}
                className={`block w-full rounded-lg px-3 py-2 text-left text-sm transition ${activeSection === s.id
                    ? "bg-emerald-500/10 font-medium text-emerald-400"
                    : "text-slate-400 hover:bg-slate-800 hover:text-white"
                  }`}
              >
                {s.title}
              </button>
            ))}
          </div>
        </aside>

        {/* Main content */}
        <main className="min-w-0 flex-1">
          <h1 className="mb-2 text-3xl font-bold">Documentation</h1>
          <p className="mb-10 text-slate-400">
            Everything you need to know about setting up and using CloudSecure.
          </p>

          <div className="space-y-16">
            {sections.map((s) => (
              <section key={s.id} id={s.id}>
                <h2 className="mb-4 text-xl font-bold text-white">{s.title}</h2>
                <div className="text-sm leading-relaxed text-slate-300">{s.content}</div>
              </section>
            ))}
          </div>
        </main>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/50">
        <div className="mx-auto max-w-7xl px-6 py-8">
          <div className="flex flex-col items-center justify-between gap-4 sm:flex-row">
            <div className="flex items-center gap-2">
              <img src="/logo.png" alt="CloudSecure" className="h-7 w-7 object-contain" />
              <span className="font-semibold">CloudSecure</span>
            </div>
            <p className="text-sm text-slate-500">
              Built by Team Kaalitopi · Cloud Security Scanner
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}