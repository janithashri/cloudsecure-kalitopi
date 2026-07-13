from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_tenant, get_current_user
from app.models.orm import AuthUser
from app.core.database import get_db
from app.db import repositories as repo
from app.models.orm import AuthUser, CustomRule, Finding, Provider, Tenant
from app.schemas.findings import CustomRuleCreate, CustomRuleOut, FindingOut
from app.schemas.gds import GDSShortestPathRequest, GDSShortestPathResponse
from app.services import gds_service
from app.services import graph_service
from worker.jobs.attack_engine import get_attack_graph, run_all_queries

router = APIRouter(tags=["analytics"])


def _provider(db: Session, tenant: Tenant, provider_id: int) -> Provider:
    p = repo.get_provider_for_tenant(db, provider_id, tenant.id)
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    return p


@router.get("/api/v1/providers/{provider_id}/inventory-summary/")
def inventory_summary(
    provider_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    return graph_service.inventory_summary(db, _provider(db, tenant, provider_id))


@router.get("/api/v1/providers/{provider_id}/graph/")
def graph_data(
    provider_id: int,
    type: str | None = Query(None, alias="type"),
    status: str | None = Query(None, alias="status"),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    return graph_service.inventory_graph_data(_provider(db, tenant, provider_id), type, status)


@router.get("/api/v1/providers/{provider_id}/graph/cartography/")
def cartography_graph(
    provider_id: int,
    label: str | None = None,
    scan_id: str | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    return graph_service.cartography_graph_data(db, _provider(db, tenant, provider_id), label, scan_id)


@router.post("/api/v1/providers/{provider_id}/attack-engine/run/")
def attack_run_all(
    provider_id: int,
    body: dict | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    provider = _provider(db, tenant, provider_id)
    scan_id = (body or {}).get("scan_id")
    update_tag = graph_service.provider_scan_update_tag(db, provider, scan_id)
    if update_tag is None:
        raise HTTPException(status_code=409, detail="Deep scan required before running attack engine")
    with graph_service.provider_graph_session(db, provider) as session:
        results = run_all_queries(provider.aws_account_id, neo4j_session=session, update_tag=update_tag)
    return {"results": results}


@router.get("/api/v1/providers/{provider_id}/attack-engine/query/{query_id}/")
def attack_single(
    provider_id: int,
    query_id: str,
    scan_id: str | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    provider = _provider(db, tenant, provider_id)
    update_tag = graph_service.provider_scan_update_tag(db, provider, scan_id)
    if update_tag is None:
        raise HTTPException(status_code=409, detail="Deep scan required before running attack engine")
    with graph_service.provider_graph_session(db, provider) as session:
        return get_attack_graph(
            query_id, provider.aws_account_id, neo4j_session=session, update_tag=update_tag
        )


@router.post("/api/v1/providers/{provider_id}/gds/shortest-path/", response_model=GDSShortestPathResponse)
def gds_shortest_path(
    provider_id: int,
    body: GDSShortestPathRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    provider = _provider(db, tenant, provider_id)
    return gds_service.shortest_path(
        db=db,
        provider=provider,
        source_node_id=body.source_node_id,
        target_node_id=body.target_node_id,
        scan_id=body.scan_id,
    )


def _matches_framework(finding: Finding, wanted: str) -> bool:
    rule_id = str(finding.rule_id or "").upper()
    if wanted in {"CIS", "DPDP", "RBI", "SBE"} and rule_id.startswith(f"{wanted}-"):
        return True
    tokens = set()
    for item in finding.compliance_frameworks or []:
        if isinstance(item, str):
            u = item.upper()
            for fw in ("CIS", "DPDP", "RBI", "SBE"):
                if u.startswith(fw):
                    tokens.add(fw)
    raw = finding.raw_finding if isinstance(finding.raw_finding, dict) else {}
    fw_val = raw.get("framework")
    if isinstance(fw_val, str):
        u = fw_val.upper()
        for fw in ("CIS", "DPDP", "RBI", "SBE"):
            if u.startswith(fw):
                tokens.add(fw)
    return wanted in tokens


@router.get("/api/v1/providers/{provider_id}/findings/")
def list_findings(
    provider_id: int,
    status: str | None = None,
    severity: str | None = None,
    resource_type: str | None = None,
    framework: str | None = None,
    page: int = Query(1, ge=1),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    _provider(db, tenant, provider_id)
    q = select(Finding).where(Finding.tenant_id == tenant.id, Finding.provider_id == provider_id)
    if status:
        q = q.where(Finding.status == status)
    if severity:
        q = q.where(Finding.severity == severity)
    if resource_type:
        q = q.where(Finding.resource_type == resource_type)
    findings = list(db.scalars(q.order_by(Finding.last_seen.desc())))
    if framework:#post processing can use gin index 
        wanted = framework.strip().upper()
        findings = [f for f in findings if _matches_framework(f, wanted)]
    page_size = 50
    start = (page - 1) * page_size
    page_items = findings[start : start + page_size]#need to use cursor pagination later
    results = []
    for f in page_items:
        rc = repo.get_resource_config(db, f.account_id, f.arn)
        results.append(
            FindingOut(
                id=f.id,
                arn=f.arn,
                resource_type=f.resource_type,
                region=f.region,
                rule_id=f.rule_id,
                rule_name=f.rule_name,
                severity=f.severity,
                status=f.status,
                compliance_frameworks=f.compliance_frameworks or [],
                remediation_steps=f.remediation_steps or "",
                resource_config=rc.config if rc else None,
                first_seen=f.first_seen,
                last_seen=f.last_seen,
            )
        )
    return {
        "count": len(findings),
        "next": page + 1 if start + page_size < len(findings) else None,
        "previous": page - 1 if page > 1 else None,
        "results": results,
    }


@router.get("/api/v1/providers/{provider_id}/findings/summary/")
def findings_summary(
    provider_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    _provider(db, tenant, provider_id)
    qs = select(Finding).where(
        Finding.tenant_id == tenant.id, Finding.provider_id == provider_id, Finding.status == "OPEN"
    )
    open_findings = list(db.scalars(qs))
    by_severity: dict[str, int] = {}
    by_resource_type: dict[str, int] = {}
    frameworks: dict[str, int] = {}
    for f in open_findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_resource_type[f.resource_type] = by_resource_type.get(f.resource_type, 0) + 1
        for x in f.compliance_frameworks or []:
            if isinstance(x, str):
                frameworks[x] = frameworks.get(x, 0) + 1
    last_run = repo.get_latest_inventory_run(db, provider_id)
    new_this_run = 0
    if last_run:
        new_this_run = db.scalar(
            select(func.count(Finding.id)).where(
                Finding.tenant_id == tenant.id,
                Finding.provider_id == provider_id,
                Finding.inventory_run_id == last_run.id,
            )
        ) or 0
    return {
        "total_open": len(open_findings),
        "by_severity": by_severity,
        "by_resource_type": by_resource_type,
        "by_framework": frameworks,
        "new_this_run": new_this_run,
    }


_FRAGMENTED_S3_PUBLIC_RULE_IDS = {
    "CIS-2.1.4",
    "CIS-2.1.4-PUBLIC",
    "CIS-2.1-CROSS-ACCOUNT",
    "DPDP-S3-PUBLIC",
    "DPDP-S3-IS-PUBLIC",
    "RBI-S3-CROSS-ACCOUNT",
}


def _is_fragmented_s3_public_rule(rule_id: str | None) -> bool:
    return str(rule_id or "") in _FRAGMENTED_S3_PUBLIC_RULE_IDS


def _validation_probe(finding: Finding) -> dict:
    raw = finding.raw_finding if isinstance(finding.raw_finding, dict) else {}
    probe = raw.get("validation_probe")
    return probe if isinstance(probe, dict) else {}


@router.get("/api/v1/providers/{provider_id}/findings/rule-effectiveness/")
def rule_effectiveness_report(
    provider_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    _provider(db, tenant, provider_id)

    all_findings = list(
        db.scalars(
            select(Finding).where(Finding.tenant_id == tenant.id, Finding.provider_id == provider_id)
        ).all()
    )

    old_rule_findings = [f for f in all_findings if _is_fragmented_s3_public_rule(f.rule_id)]
    consolidated_findings = [f for f in all_findings if f.rule_id == "CONSOLIDATED-S3-001"]
    validated_true = [
        f
        for f in consolidated_findings
        if _validation_probe(f).get("classification") == "true_positive"
    ]
    validated_false = [
        f
        for f in consolidated_findings
        if _validation_probe(f).get("classification") == "false_positive"
        or f.status == "COMPENSATING_CONTROL_DETECTED"
    ]

    s3_probed = [f for f in consolidated_findings if _validation_probe(f).get("probe_type") == "s3_unauth_head_get"]
    iam_probed = [
        f for f in all_findings if _validation_probe(f).get("probe_type") == "iam_access_key_liveness"
    ]

    old_count = len(old_rule_findings)
    consolidated_count = len(consolidated_findings)
    validated_count = len(validated_true)

    fragmented_rule_types = len(_FRAGMENTED_S3_PUBLIC_RULE_IDS)

    return {
        "stage_1_consolidation": {
            "fragmented_rule_types": fragmented_rule_types,
            "consolidated_rule_types": 1,
            "old_alert_count": old_count,
            "consolidated_alert_count": consolidated_count,
            "reduction_pct": round((1 - consolidated_count / old_count) * 100, 1) if old_count else 0,
            "paper": "Precision over Noise (arXiv 2508.14402)",
        },
        "stage_2_validation": {
            "s3_probes_run": len(s3_probed),
            "iam_probes_run": len(iam_probed),
            "confirmed_true_positive": validated_count,
            "compensating_control_detected": len(validated_false),
            "additional_reduction_pct": round((1 - validated_count / consolidated_count) * 100, 1)
            if consolidated_count
            else 0,
            "paper": "Alert or Noise? (arXiv 2508.12584)",
        },
        "combined_funnel": {
            "old": old_count,
            "consolidated": consolidated_count,
            "validated": validated_count,
        },
        "downgraded_findings": [
            {
                "arn": f.arn,
                "rule_id": f.rule_id,
                "resource_label": f.arn.split(":::")[-1] if ":::" in f.arn else f.arn,
                "probe_type": _validation_probe(f).get("probe_type"),
                "compensating_control": _validation_probe(f).get("compensating_control"),
                "http_status": _validation_probe(f).get("http_status"),
                "duration_ms": _validation_probe(f).get("duration_ms"),
                "matched_condition": (f.raw_finding or {}).get("matched_condition")
                if isinstance(f.raw_finding, dict)
                else None,
            }
            for f in validated_false
        ],
        "confirmed_findings": [
            {
                "arn": f.arn,
                "rule_id": f.rule_id,
                "resource_label": f.arn.split(":::")[-1] if ":::" in f.arn else f.arn,
                "probe_type": _validation_probe(f).get("probe_type"),
                "classification": _validation_probe(f).get("classification"),
                "http_status": _validation_probe(f).get("http_status"),
                "matched_condition": (f.raw_finding or {}).get("matched_condition")
                if isinstance(f.raw_finding, dict)
                else None,
            }
            for f in validated_true
            if _validation_probe(f)
        ],
    }


@router.patch("/api/v1/findings/{finding_id}/suppress/", status_code=200)
def suppress_finding(
    finding_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.tenant_id == tenant.id))
    if not finding:
        raise HTTPException(status_code=404, detail="Not found")
    finding.status = "SUPPRESSED"
    db.commit()
    return {}


@router.get("/api/v1/custom-rules/", response_model=list[CustomRuleOut])
def list_custom_rules(
    provider_id: int | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    q = select(CustomRule).where(CustomRule.tenant_id == tenant.id).order_by(CustomRule.created_at.desc())
    if provider_id:
        q = q.where(CustomRule.provider_id == provider_id)
    return list(db.scalars(q))


@router.post("/api/v1/custom-rules/", response_model=CustomRuleOut, status_code=201)
def create_custom_rule(
    body: CustomRuleCreate,
    tenant: Tenant = Depends(get_current_tenant),
    user: AuthUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    now = repo.utcnow()
    rule = CustomRule(
        tenant_id=tenant.id,
        provider_id=body.provider,
        name=body.name,
        resource_type=body.resource_type,
        rule_id=body.rule_id,
        severity=body.severity,
        compliance_frameworks=body.compliance_frameworks,
        description=body.description,
        rego_policy=body.rego_policy,
        enabled=body.enabled,
        created_by_id=user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule
