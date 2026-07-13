"""
Maps AWS CloudTrail event names to 14 semantic action categories.
This is critical: without categorisation, Node2Vec cannot learn patterns
because every event name is too unique.
"""

from __future__ import annotations

from collections import Counter

ACTION_CATEGORIES: dict[str, list[str]] = {
    "ListResources": [
        "ListBuckets",
        "ListObjects",
        "ListUsers",
        "ListRoles",
        "ListPolicies",
        "ListInstances",
        "ListFunctions",
        "ListSecrets",
        "ListKeys",
        "ListGroups",
        "ListAttachedRolePolicies",
        "ListAccessKeys",
        "ListMFADevices",
        "ListVirtualMFADevices",
        "ListAccountAliases",
        "DescribeInstances",
        "DescribeSecurityGroups",
        "DescribeVpcs",
        "DescribeSubnets",
        "DescribeImages",
        "DescribeKeyPairs",
    ],
    "GetInfo": [
        "GetUser",
        "GetRole",
        "GetPolicy",
        "GetBucketPolicy",
        "GetBucketAcl",
        "GetPublicAccessBlock",
        "DescribeTrails",
        "GetCallerIdentity",
        "GetAccountSummary",
        "GetLoginProfile",
        "DescribeDBInstances",
    ],
    "SensitiveInfo": [
        "GetSecretValue",
        "GetParameter",
        "GetParameters",
        "GetParametersByPath",
        "GetObject",
        "DownloadDBLogFilePortion",
        "GetAuthorizationToken",
        "GenerateDataKey",
        "Decrypt",
    ],
    "GrantPermissions": [
        "AttachRolePolicy",
        "AttachUserPolicy",
        "AttachGroupPolicy",
        "PutRolePolicy",
        "PutUserPolicy",
        "PutGroupPolicy",
        "PutBucketPolicy",
        "PutBucketAcl",
        "PutObjectAcl",
        "AddUserToGroup",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "AddRoleToInstanceProfile",
    ],
    "RevokePermissions": [
        "DetachRolePolicy",
        "DetachUserPolicy",
        "DeleteRolePolicy",
        "DeleteUserPolicy",
        "RemoveUserFromGroup",
        "DeletePolicyVersion",
        "DeleteBucketPolicy",
    ],
    "CreateResource": [
        "CreateUser",
        "CreateRole",
        "CreateGroup",
        "CreatePolicy",
        "CreateBucket",
        "CreateFunction",
        "CreateSecret",
        "CreateKey",
        "CreateInstance",
        "RunInstances",
        "CreateDBInstance",
        "CreateVpc",
        "CreateSubnet",
        "CreateSecurityGroup",
        "CreateAccessKey",
        "CreateLoginProfile",
        "CreateInstanceProfile",
    ],
    "DeleteResource": [
        "DeleteUser",
        "DeleteRole",
        "DeleteGroup",
        "DeletePolicy",
        "DeleteBucket",
        "DeleteFunction",
        "DeleteSecret",
        "DeleteKey",
        "TerminateInstances",
        "DeleteDBInstance",
        "DeleteVpc",
        "DeleteSecurityGroup",
        "DeleteAccessKey",
        "DeleteLoginProfile",
        "DeleteTrail",
        "DeleteFlowLogs",
    ],
    "ModifyResource": [
        "UpdateUser",
        "UpdateRole",
        "UpdateGroup",
        "UpdateFunction",
        "ModifyDBInstance",
        "UpdateSecret",
        "RotateSecret",
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "ModifyInstanceAttribute",
        "UpdateLoginProfile",
        "EnableMFADevice",
        "DeactivateMFADevice",
    ],
    "Authentication": [
        "ConsoleLogin",
        "AssumeRole",
        "AssumeRoleWithWebIdentity",
        "AssumeRoleWithSAML",
        "GetFederationToken",
        "GetSessionToken",
        "SwitchRole",
    ],
    "NetworkConfig": [
        "CreateVpc",
        "CreateSubnet",
        "CreateInternetGateway",
        "CreateRouteTable",
        "CreateRoute",
        "CreateNatGateway",
        "ModifyVpcAttribute",
        "EnableVpcClassicLink",
        "CreateTransitGateway",
        "CreateVpcPeeringConnection",
        "AttachInternetGateway",
        "AssociateRouteTable",
    ],
    "DataTransfer": [
        "PutObject",
        "CopyObject",
        "UploadPart",
        "CompleteMultipartUpload",
        "CreateMultipartUpload",
        "RestoreObject",
        "PutBucketReplication",
        "PutBucketCORS",
    ],
    "MonitoringConfig": [
        "CreateTrail",
        "StartLogging",
        "StopLogging",
        "UpdateTrail",
        "DeleteTrail",
        "PutEventSelectors",
        "CreateAlarm",
        "DeleteAlarm",
        "PutMetricAlarm",
        "CreateLogGroup",
        "CreateLogStream",
        "PutLogEvents",
        "EnableFlowLogs",
        "DeleteFlowLogs",
    ],
    "BillingCost": [
        "StartInstances",
        "StopInstances",
        "RebootInstances",
        "RunInstances",
        "ModifyReservedInstances",
        "PurchaseReservedInstancesOffering",
        "CreateSpotInstanceRequests",
    ],
    "Unknown": [],
}

PREFIX_RULES: dict[str, str] = {
    "List": "ListResources",
    "Describe": "GetInfo",
    "Get": "GetInfo",
    "Create": "CreateResource",
    "Delete": "DeleteResource",
    "Update": "ModifyResource",
    "Modify": "ModifyResource",
    "Put": "DataTransfer",
    "Attach": "GrantPermissions",
    "Detach": "RevokePermissions",
    "Enable": "MonitoringConfig",
    "Disable": "MonitoringConfig",
    "Start": "BillingCost",
    "Stop": "BillingCost",
    "Terminate": "DeleteResource",
    "Run": "CreateResource",
    "Assume": "Authentication",
}

_EVENT_TO_CATEGORY: dict[str, str] = {}
for category, names in ACTION_CATEGORIES.items():
    if category == "Unknown":
        continue
    for name in names:
        _EVENT_TO_CATEGORY[name] = category


def categorise_event(event_name: str) -> str:
    """
    Maps an event name to one of 14 action categories.
    First tries exact match, then prefix match (List*, Get*, etc.),
    then falls back to 'Unknown'.
    """
    if not event_name:
        return "Unknown"

    exact = _EVENT_TO_CATEGORY.get(event_name)
    if exact:
        return exact

    for prefix, category in PREFIX_RULES.items():
        if event_name.startswith(prefix):
            return category

    return "Unknown"


def categorise_events(events: list[dict]) -> list[dict]:
    """Adds 'action_category' field to each event dict. Returns modified list."""
    for event in events:
        event["action_category"] = categorise_event(event.get("event_name", ""))
    return events


def get_category_distribution(events: list[dict]) -> dict[str, int]:
    """Returns count of events per category."""
    counts: Counter[str] = Counter()
    for event in events:
        category = event.get("action_category") or categorise_event(event.get("event_name", ""))
        counts[category] += 1
    return dict(counts)


if __name__ == "__main__":
    import sys

    from worker.jobs.anomaly_detection.cloudtrail_parser import parse_directory

    dataset_dir = (
        sys.argv[1]
        if len(sys.argv) > 1
        else r"C:\Users\Admin\Downloads\aws_dataset-main\aws_dataset-main"
    )

    tests = [
        ("ListBuckets", "ListResources"),
        ("GetSecretValue", "SensitiveInfo"),
        ("AttachRolePolicy", "GrantPermissions"),
        ("ConsoleLogin", "Authentication"),
        ("SomeNewEventName", "Unknown"),
    ]
    print("Unit tests:")
    for event_name, expected in tests:
        if event_name == "SomeNewEventName":
            result = categorise_event("DescribeNewThing")
            print(f"  DescribeNewThing -> {result} (prefix match)")
            continue
        result = categorise_event(event_name)
        status = "OK" if result == expected else f"FAIL (got {result})"
        print(f"  {event_name} -> {result} [{status}]")

    events = categorise_events(parse_directory(dataset_dir))
    distribution = get_category_distribution(events)
    total = sum(distribution.values())
    unknown_pct = 100.0 * distribution.get("Unknown", 0) / total if total else 0
    print(f"\nCategory distribution ({total} events):")
    for category, count in sorted(distribution.items(), key=lambda x: -x[1]):
        print(f"  {category}: {count} ({100.0 * count / total:.1f}%)")
    print(f"Unknown percentage: {unknown_pct:.1f}%")
