ATTACK_QUERIES = [
    {
        "id": "ATK-001",
        "name": "Public EC2 with Admin IAM Role",
        "mitre_technique": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "mitre_tactic": "Initial Access",
        "severity": "CRITICAL",
        "description": "A publicly exposed EC2 security group and role-assumption chain to admin policy enables fast account takeover.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(sg:EC2SecurityGroup)
            MATCH (sg)-[:ALLOWS_TRAFFIC_FROM]->(ipr:AWSIpRange)
            WHERE coalesce(ipr.range, "") IN ["0.0.0.0/0", "::/0"]
            MATCH (a)-[:RESOURCE]->(r:AWSRole)-[:POLICY]->(p:AWSPolicy)
            WHERE coalesce(p.name, "") = "AdministratorAccess"
            RETURN a, sg, ipr, r, p
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "EC2SecurityGroup", "AWSIpRange", "AWSRole", "AWSPolicy"],
        "remediation": "Restrict public ingress and remove AdministratorAccess from instance-associated roles.",
        "references": [
            "https://attack.mitre.org/techniques/T1078/004/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        ],
    },
    {
        "id": "ATK-002",
        "name": "Publicly Reachable Data Plane with Missing Encryption",
        "mitre_technique": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "mitre_tactic": "Initial Access",
        "severity": "HIGH",
        "description": "Public traffic allowed and weak storage encryption posture increase exploit risk on internet-facing data paths.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(sg:EC2SecurityGroup)-[:ALLOWS_TRAFFIC_FROM]->(ipr:AWSIpRange)
            WHERE coalesce(ipr.range, "") IN ["0.0.0.0/0", "::/0"]
            MATCH (a)-[:RESOURCE]->(b:S3Bucket)
            WHERE coalesce(b.default_encryption, false) = false
            RETURN a, sg, ipr, b
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "EC2SecurityGroup", "AWSIpRange", "S3Bucket"],
        "remediation": "Close broad ingress rules and enforce encryption at rest for reachable data stores.",
        "references": [
            "https://attack.mitre.org/techniques/T1190/",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html",
        ],
    },
    {
        "id": "ATK-003",
        "name": "Public S3 Bucket with Sensitive Tag Indicators",
        "mitre_technique": "T1199",
        "mitre_name": "Trusted Relationship",
        "mitre_tactic": "Initial Access",
        "severity": "HIGH",
        "description": "Public bucket indicators combined with sensitive tags expose data through trusted sharing boundaries.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(b:S3Bucket)
            WHERE coalesce(b.anonymous_access, false) = true
               OR coalesce(b.block_public_policy, false) = false
               OR coalesce(b.ignore_public_acls, false) = false
            OPTIONAL MATCH (b)-[:TAGGED]->(t:Tag)
            WITH a, b, collect(t) AS tags
            WHERE any(tag IN tags WHERE toLower(coalesce(tag.key, "") + ":" + coalesce(tag.value, "")) CONTAINS "sensitive")
               OR size(tags) = 0
            RETURN a, b, tags
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "S3Bucket", "Tag"],
        "remediation": "Block public access, enforce bucket policies, and classify sensitive objects with strict controls.",
        "references": [
            "https://attack.mitre.org/techniques/T1199/",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ],
    },
    {
        "id": "ATK-004",
        "name": "Role with PassRole-Like Privilege Escalation",
        "mitre_technique": "T1484.001",
        "mitre_name": "Domain Policy Modification: Group Policy Modification",
        "mitre_tactic": "Privilege Escalation",
        "severity": "CRITICAL",
        "description": "Role policy allows privilege-management actions that can be chained into high-privilege role abuse.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(r:AWSRole)-[:POLICY]->(p:AWSPolicy)-[:STATEMENT]->(s:AWSPolicyStatement)
            WHERE any(act IN coalesce(s.action, []) WHERE act IN ["iam:PassRole", "iam:AttachRolePolicy", "iam:PutRolePolicy"])
            RETURN a, r, p, s
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "AWSRole", "AWSPolicy", "AWSPolicyStatement"],
        "remediation": "Deny iam:PassRole and role-policy mutation except for tightly scoped automation principals.",
        "references": [
            "https://attack.mitre.org/techniques/T1484/001/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
        ],
    },
    {
        "id": "ATK-005",
        "name": "IAM User with AdministratorAccess",
        "mitre_technique": "T1548",
        "mitre_name": "Abuse Elevation Control Mechanism",
        "mitre_tactic": "Privilege Escalation",
        "severity": "CRITICAL",
        "description": "Direct admin policy on IAM users removes guardrails and enables immediate privilege abuse.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(u:AWSUser)-[:POLICY]->(p:AWSPolicy)
            WHERE coalesce(p.name, "") = "AdministratorAccess"
            RETURN a, u, p
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "AWSUser", "AWSPolicy"],
        "remediation": "Detach AdministratorAccess from users; migrate to least-privilege role-based access.",
        "references": [
            "https://attack.mitre.org/techniques/T1548/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        ],
    },
    {
        "id": "ATK-006",
        "name": "Principal Can Create IAM Identities",
        "mitre_technique": "T1098",
        "mitre_name": "Account Manipulation",
        "mitre_tactic": "Privilege Escalation",
        "severity": "HIGH",
        "description": "Policy actions that create users, roles, or keys enable durable unauthorized persistence and escalation.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(pr:AWSPrincipal)-[:POLICY]->(p:AWSPolicy)-[:STATEMENT]->(s:AWSPolicyStatement)
            WHERE any(act IN coalesce(s.action, []) WHERE act IN ["iam:CreateUser", "iam:CreateRole", "iam:CreateAccessKey", "iam:PutUserPolicy"])
            RETURN a, pr, p, s
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "AWSPrincipal", "AWSPolicy", "AWSPolicyStatement"],
        "remediation": "Restrict identity-creation IAM actions to break-glass workflows with approvals.",
        "references": [
            "https://attack.mitre.org/techniques/T1098/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html",
        ],
    },
    {
        "id": "ATK-007",
        "name": "Wildcard AssumeRole Permissions",
        "mitre_technique": "T1484",
        "mitre_name": "Domain or Tenant Policy Manipulation",
        "mitre_tactic": "Privilege Escalation",
        "severity": "HIGH",
        "description": "Wildcard role assumption permissions enable broad movement into higher-privileged identities.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(pr:AWSPrincipal)-[:POLICY]->(p:AWSPolicy)-[:STATEMENT]->(s:AWSPolicyStatement)
            WHERE any(act IN coalesce(s.action, []) WHERE act IN ["sts:AssumeRole", "sts:*"])
              AND any(res IN coalesce(s.resource, []) WHERE res = "*" OR res CONTAINS ":role/")
            RETURN a, pr, p, s
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "AWSPrincipal", "AWSPolicy", "AWSPolicyStatement"],
        "remediation": "Scope sts:AssumeRole resources to explicit role ARNs and condition on source identity.",
        "references": [
            "https://attack.mitre.org/techniques/T1484/",
            "https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html",
        ],
    },
    {
        "id": "ATK-008",
        "name": "Cross-Account Trust Enables Lateral Movement",
        "mitre_technique": "T1021.007",
        "mitre_name": "Remote Services: Cloud Services",
        "mitre_tactic": "Lateral Movement",
        "severity": "HIGH",
        "description": "Roles trusted by foreign principals create cross-account movement paths.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(r:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(p:AWSPrincipal)
            WHERE coalesce(p.arn, "") CONTAINS ":iam::"
              AND NOT coalesce(p.arn, "") CONTAINS ":" + $account_id + ":"
            RETURN a, r, p
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "AWSRole", "AWSPrincipal"],
        "remediation": "Constrain trust policies to approved account IDs and add external ID conditions.",
        "references": [
            "https://attack.mitre.org/techniques/T1021/007/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html",
        ],
    },
    {
        "id": "ATK-009",
        "name": "Role Trusted by Multiple Principals",
        "mitre_technique": "T1550",
        "mitre_name": "Use Alternate Authentication Material",
        "mitre_tactic": "Lateral Movement",
        "severity": "HIGH",
        "description": "Wide trust fan-out increases blast radius if any trusted account/principal is compromised.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(r:AWSRole)<-[:TRUSTS_AWS_PRINCIPAL]-(p:AWSPrincipal)
            WITH a, r, collect(p) AS principals
            WHERE size(principals) >= 2
            RETURN a, r, principals
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "AWSRole", "AWSPrincipal"],
        "remediation": "Minimize trust relationships and segment high-privilege roles by workload purpose.",
        "references": [
            "https://attack.mitre.org/techniques/T1550/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html",
        ],
    },
    {
        "id": "ATK-010",
        "name": "Public Perimeter with Broad Egress Potential",
        "mitre_technique": "T1534",
        "mitre_name": "Internal Spearphishing",
        "mitre_tactic": "Lateral Movement",
        "severity": "MEDIUM",
        "description": "Public ingress and permissive route topology can support external callback/lateral staging.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(sg:EC2SecurityGroup)-[:ALLOWS_TRAFFIC_FROM]->(ipr:AWSIpRange)
            WHERE coalesce(ipr.range, "") = "0.0.0.0/0"
            OPTIONAL MATCH (a)-[:RESOURCE]->(rt:EC2RouteTable)-[:ROUTE]->(r:EC2Route)-[:ROUTES_TO_GATEWAY]->(igw:AWSInternetGateway)
            RETURN a, sg, ipr, rt, r, igw
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "EC2SecurityGroup", "AWSIpRange", "EC2RouteTable", "EC2Route", "AWSInternetGateway"],
        "remediation": "Limit ingress CIDRs and enforce controlled egress through inspected gateways.",
        "references": [
            "https://attack.mitre.org/techniques/T1534/",
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
        ],
    },
    {
        "id": "ATK-011",
        "name": "CloudTrail Logging Weakness",
        "mitre_technique": "T1562.008",
        "mitre_name": "Impair Defenses: Disable or Modify Cloud Logs",
        "mitre_tactic": "Defense Evasion",
        "severity": "HIGH",
        "description": "Missing or weak CloudTrail/Config recorder coverage reduces forensic visibility.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})
            OPTIONAL MATCH (a)-[:RESOURCE]->(rec:AWSConfigurationRecorder)
            OPTIONAL MATCH (a)-[:RESOURCE]->(del:AWSConfigDeliveryChannel)
            WITH a, collect(rec) AS recs, collect(del) AS dels
            WHERE size(recs) = 0 OR size(dels) = 0
            RETURN a, recs, dels
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "AWSConfigurationRecorder", "AWSConfigDeliveryChannel"],
        "remediation": "Enable multi-region audit logging and ensure delivery channels are healthy.",
        "references": [
            "https://attack.mitre.org/techniques/T1562/008/",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html",
        ],
    },
    {
        "id": "ATK-012",
        "name": "Security Group Open to Internet",
        "mitre_technique": "T1562.001",
        "mitre_name": "Impair Defenses: Disable or Modify Tools",
        "mitre_tactic": "Defense Evasion",
        "severity": "HIGH",
        "description": "Internet-open security group rules bypass perimeter assumptions.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(sg:EC2SecurityGroup)-[:ALLOWS_TRAFFIC_FROM]->(ipr:AWSIpRange)
            WHERE coalesce(ipr.range, "") IN ["0.0.0.0/0", "::/0"]
            RETURN a, sg, ipr
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "EC2SecurityGroup", "AWSIpRange"],
        "remediation": "Replace 0.0.0.0/0 and ::/0 with approved CIDR allowlists.",
        "references": [
            "https://attack.mitre.org/techniques/T1562/001/",
            "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
        ],
    },
    {
        "id": "ATK-013",
        "name": "Console-Capable IAM User Without MFA Indicators",
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
        "mitre_tactic": "Defense Evasion",
        "severity": "HIGH",
        "description": "Long-lived IAM users with console activity and weak MFA posture increase account takeover risk.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(u:AWSUser)
            OPTIONAL MATCH (u)-[:POLICY]->(p:AWSPolicy)-[:STATEMENT]->(s:AWSPolicyStatement)
            WITH a, u, collect(s) AS statements
            WHERE any(st IN statements WHERE any(act IN coalesce(st.action, []) WHERE act IN ["iam:CreateAccessKey", "iam:CreateLoginProfile", "*"]))
               OR coalesce(u.last_authenticated, "") <> ""
            RETURN a, u
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "AWSUser"],
        "remediation": "Enforce MFA, disable unused console users, and migrate to role-based federation.",
        "references": [
            "https://attack.mitre.org/techniques/T1078/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
        ],
    },
    {
        "id": "ATK-014",
        "name": "Principal Read Access to Weakly Protected Bucket",
        "mitre_technique": "T1537",
        "mitre_name": "Transfer Data to Cloud Account",
        "mitre_tactic": "Exfiltration",
        "severity": "HIGH",
        "description": "Principal with S3 read actions and weak bucket controls enables staged exfiltration.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(pr:AWSPrincipal)-[:POLICY]->(p:AWSPolicy)-[:STATEMENT]->(s:AWSPolicyStatement)
            WHERE any(act IN coalesce(s.action, []) WHERE act IN ["s3:GetObject", "s3:*", "*"])
            MATCH (a)-[:RESOURCE]->(b:S3Bucket)
            WHERE coalesce(b.default_encryption, false) = false OR coalesce(b.anonymous_access, false) = true
            RETURN a, pr, p, s, b
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "AWSPrincipal", "AWSPolicy", "AWSPolicyStatement", "S3Bucket"],
        "remediation": "Constrain S3 read permissions and enforce encryption/public-access blocks on buckets.",
        "references": [
            "https://attack.mitre.org/techniques/T1537/",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html",
        ],
    },
    {
        "id": "ATK-015",
        "name": "Public Bucket Without Access Logging",
        "mitre_technique": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "mitre_tactic": "Exfiltration",
        "severity": "HIGH",
        "description": "Public bucket exposure without logging creates blind spots for data exfiltration detection.",
        "cypher": """
            MATCH (a:AWSAccount {id: $account_id})-[:RESOURCE]->(b:S3Bucket)
            WHERE (coalesce(b.anonymous_access, false) = true OR coalesce(b.block_public_policy, false) = false)
              AND coalesce(b.logging_enabled, false) = false
            RETURN a, b
            LIMIT 100
        """,
        "path_nodes": ["AWSAccount", "S3Bucket"],
        "remediation": "Enable server-access logging and fully block public access on sensitive buckets.",
        "references": [
            "https://attack.mitre.org/techniques/T1530/",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
        ],
    },
]


ATTACK_QUERY_MAP = {q["id"]: q for q in ATTACK_QUERIES}
