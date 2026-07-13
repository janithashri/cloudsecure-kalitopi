from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.conf import settings
from contextlib import contextmanager
import json
import neo4j
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404

from accounts.models import Tenant, UserProfile
from api.models import DeepScan
from api.models import DeepScanStateChoices as DeepScanStateChoices
from api.models import CustomRule, Finding, InventoryRun
from api.serializers import CustomRuleSerializer, FindingSerializer
from providers.models import Provider
from tasks.jobs.attack_engine import ATTACK_QUERIES
from tasks.jobs.attack_engine import get_attack_graph
from tasks.jobs.attack_engine import run_all_queries
from tasks.jobs.inventory.neo4j_writer import get_neo4j_driver

_tenant_graph_driver_cache: dict[str, neo4j.Driver] = {}


def _json_safe(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    # Neo4j temporal/spatial types and other custom values
    return str(value)


def _graph_node_id(props: dict) -> str:
    for key in ("id", "arn", "name", "provider_element_id", "groupid", "subnetid"):
        value = props.get(key)
        if value:
            return str(value)
    return str(hash(tuple(sorted(props.items()))))


def _graph_node_label(props: dict, labels: list[str]) -> str:
    raw = str(props.get("name") or props.get("id") or props.get("arn") or (labels[0] if labels else "Node"))
    if raw.startswith("arn:"):
        tail = raw.split("/")[-1] if "/" in raw else raw.split(":")[-1]
        return tail or raw
    return raw


def _provider_graph_database(provider: Provider, scan_id: str | None = None) -> str:
    if scan_id:
        scan = (
            DeepScan.objects.filter(
                tenant_id=provider.tenant_id,
                provider_id=provider.id,
                scan_id=scan_id,
                is_graph_database_deleted=False,
            )
            .order_by("-completed_at", "-started_at")
            .first()
        )
        if scan and scan.graph_database:
            return scan.graph_database

    latest_scan = (
        DeepScan.objects.filter(
            tenant_id=provider.tenant_id,
            provider_id=provider.id,
            state=DeepScanStateChoices.COMPLETED,
            is_graph_database_deleted=False,
        )
        .order_by("-completed_at", "-started_at")
        .first()
    )
    if latest_scan and latest_scan.graph_database:
        return latest_scan.graph_database
    return getattr(settings, "NEO4J_SHARED_DATABASE", "neo4j")


def _provider_scan_update_tag(provider: Provider, scan_id: str | None = None) -> int | None:
    if scan_id:
        scan = (
            DeepScan.objects.filter(
                tenant_id=provider.tenant_id,
                provider_id=provider.id,
                scan_id=scan_id,
                is_graph_database_deleted=False,
            )
            .order_by("-completed_at", "-started_at")
            .first()
        )
        if scan and scan.update_tag is not None:
            return int(scan.update_tag)

    latest_scan = (
        DeepScan.objects.filter(
            tenant_id=provider.tenant_id,
            provider_id=provider.id,
            state=DeepScanStateChoices.COMPLETED,
            is_graph_database_deleted=False,
            update_tag__isnull=False,
        )
        .order_by("-completed_at", "-started_at")
        .first()
    )
    if latest_scan and latest_scan.update_tag is not None:
        return int(latest_scan.update_tag)
    return None


def _get_tenant_graph_driver(tenant_id: str) -> neo4j.Driver:
    from tasks.jobs.deep_scan.utils import _build_tenant_neo4j_uri

    tenant_uri = _build_tenant_neo4j_uri(str(tenant_id))
    auth_candidates: list[tuple[str, str]] = []
    tenant_user = getattr(settings, "NEO4J_TENANT_USER", "") or ""
    tenant_password = getattr(settings, "NEO4J_TENANT_PASSWORD", "") or ""
    shared_user = getattr(settings, "NEO4J_SHARED_USER", settings.NEO4J_USER)
    shared_password = getattr(settings, "NEO4J_SHARED_PASSWORD", settings.NEO4J_PASSWORD)

    if tenant_user:
        auth_candidates.append((tenant_user, tenant_password))
    if (shared_user, shared_password) not in auth_candidates:
        auth_candidates.append((shared_user, shared_password))

    last_exc = None
    for user, password in auth_candidates:
        cache_key = f"{tenant_uri}|{user}"
        if cache_key not in _tenant_graph_driver_cache:
            _tenant_graph_driver_cache[cache_key] = neo4j.GraphDatabase.driver(
                tenant_uri,
                auth=(user, password),
            )
        driver = _tenant_graph_driver_cache[cache_key]
        try:
            driver.verify_connectivity()
            return driver
        except Exception as exc:
            last_exc = exc
            continue
    if last_exc:
        raise last_exc
    raise RuntimeError("Unable to initialize Neo4j tenant graph driver")


@contextmanager
def _provider_graph_session(provider: Provider, scan_id: str | None = None):
    database = _provider_graph_database(provider, scan_id=scan_id)
    tenant_template = getattr(settings, "NEO4J_TENANT_URI_TEMPLATE", "") or ""
    # If tenant DB URI template is not configured, use shared driver directly.
    if not tenant_template.strip():
        shared_driver = get_neo4j_driver()
        with shared_driver.session(database=database) as session:
            yield session
        return

    driver = _get_tenant_graph_driver(str(provider.tenant_id))
    with driver.session(database=database) as session:
        yield session


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username", "").strip()
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "")

        if not username or not password:
            return Response(
                {"detail": "username and password required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(username=username).exists():
            return Response(
                {"username": ["A user with this username already exists."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.create_user(
            username=username,
            email=email or username,
            password=password,
        )
        tenant = Tenant.objects.create(name=f"{username}'s workspace")
        UserProfile.objects.create(user=user, tenant=tenant)

        return Response(
            {"detail": "Account created successfully"},
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if not username or not password:
            return Response(
                {"detail": "username and password required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user = authenticate(request, username=username, password=password)
        if user is None:
            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            "token": token.key,
            "user": {
                "id": user.id,
                "email": getattr(user, "email", "") or user.username,
                "username": user.username,
            },
        })


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            request.user.auth_token.delete()
        except Exception:
            pass
        return Response(status=status.HTTP_200_OK)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        tenant_id = None
        if hasattr(user, "profile") and user.profile.tenant_id:
            tenant_id = user.profile.tenant_id
        return Response({
            "id": user.id,
            "email": getattr(user, "email", "") or user.username,
            "username": user.username,
            "tenant_id": tenant_id,
        })


def _short_label_from_arn(arn: str) -> str:
    if not arn:
        return ""
    if ":::" in arn:
        return arn.split(":::")[-1]
    parts = arn.split("/")
    return parts[-1] if parts else arn


class InventorySummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, provider_id: int):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=provider_id, tenant=tenant)
        account_id = provider.aws_account_id

        by_type: dict[str, int] = {}
        total_resources = 0
        active_resources = 0
        deleted_resources = 0

        driver = get_neo4j_driver()
        try:
            with driver.session() as session:
                rows = session.run(
                    """
                    MATCH (r:Resource)-[:BELONGS_TO]->(a:AWSAccount {account_id: $account_id})
                    RETURN r.type AS type, r.status AS status, count(r) AS count
                    """,
                    account_id=account_id,
                )
                for row in rows:
                    r_type = row.get("type") or "unknown"
                    r_status = row.get("status") or "UNKNOWN"
                    c = int(row.get("count") or 0)
                    by_type[r_type] = by_type.get(r_type, 0) + c
                    total_resources += c
                    if r_status == "ACTIVE":
                        active_resources += c
                    elif r_status == "DELETED":
                        deleted_resources += c
        except Exception:
            # Empty graph or Neo4j down: return zeros, never crash dashboard.
            by_type = {}
            total_resources = 0
            active_resources = 0
            deleted_resources = 0

        last_run = (
            InventoryRun.objects.filter(provider=provider)
            .order_by("-started_at")
            .first()
        )
        last_run_payload = None
        if last_run:
            last_run_payload = {
                "state": last_run.state,
                "started_at": last_run.started_at,
                "completed_at": last_run.completed_at,
                "stats": last_run.stats or {},
            }

        return Response(
            {
                "total_resources": total_resources,
                "by_type": by_type,
                "active_resources": active_resources,
                "deleted_resources": deleted_resources,
                "last_run": last_run_payload,
            }
        )


class GraphDataView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, provider_id: int):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=provider_id, tenant=tenant)
        account_id = provider.aws_account_id

        type_filter = request.query_params.get("type")
        status_filter = request.query_params.get("status")

        driver = get_neo4j_driver()

        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        # Always include account root node.
        nodes[account_id] = {
            "id": account_id,
            "label": account_id,
            "type": "AWSAccount",
            "region": "global",
            "status": "ACTIVE",
            "account_id": account_id,
            "properties": {},
        }

        params = {
            "account_id": account_id,
            "type": type_filter,
            "status": status_filter,
        }

        try:
            with driver.session() as session:
                # Nodes (resources + account)
                result = session.run(
                    """
                    MATCH (r:Resource)-[:BELONGS_TO]->(a:AWSAccount {account_id: $account_id})
                    WHERE ($type IS NULL OR r.type = $type)
                      AND ($status IS NULL OR r.status = $status)
                    RETURN r, a
                    """,
                    **params,
                )
                for row in result:
                    r = row.get("r")
                    if not r:
                        continue
                    arn = r.get("arn")
                    if not arn:
                        continue

                    config_raw = r.get("config") or ""
                    try:
                        properties = json.loads(config_raw) if config_raw else {}
                        if not isinstance(properties, dict):
                            properties = {}
                    except Exception:
                        properties = {}

                    nodes[arn] = {
                        "id": arn,
                        "label": _short_label_from_arn(arn),
                        "type": r.get("type"),
                        "region": r.get("region"),
                        "status": r.get("status") or "UNKNOWN",
                        "account_id": account_id,
                        "properties": properties,
                    }

                # BELONGS_TO edges
                for node_id, node in list(nodes.items()):
                    if node.get("type") == "AWSAccount":
                        continue
                    edges.append(
                        {
                            "id": f"edge-belongs-{node_id}",
                            "source": node_id,
                            "target": account_id,
                            "relationship": "BELONGS_TO",
                        }
                    )

                # Other edges
                rel_rows = session.run(
                    """
                    MATCH (r:Resource)-[:BELONGS_TO]->(a:AWSAccount {account_id: $account_id})
                    WHERE ($type IS NULL OR r.type = $type)
                      AND ($status IS NULL OR r.status = $status)
                    MATCH (r)-[rel]->(target)
                    WHERE r.arn STARTS WITH 'arn:aws'
                    RETURN r.arn AS source,
                           coalesce(target.arn, target.account_id, target.vpc_id, target.group_id) AS target,
                           type(rel) AS relationship
                    """,
                    **params,
                )
                i = 0
                for row in rel_rows:
                    source = row.get("source")
                    target = row.get("target")
                    relationship = row.get("relationship")
                    if not source or not target or not relationship:
                        continue
                    edges.append(
                        {
                            "id": f"edge-{i}",
                            "source": source,
                            "target": target,
                            "relationship": relationship,
                        }
                    )
                    i += 1

        except Exception:
            # Empty graph or Neo4j down: return minimal shape.
            return Response({"nodes": [], "edges": []})

        return Response({"nodes": list(nodes.values()), "edges": edges})


class CartographyGraphView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, provider_id: int):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=provider_id, tenant=tenant)
        account_id = provider.aws_account_id
        label_filter = request.query_params.get("label")
        scan_id = request.query_params.get("scan_id")
        update_tag = _provider_scan_update_tag(provider, scan_id=scan_id)
        if update_tag is None:
            # Strict isolation: no snapshot tag means no graph visibility.
            # Prevents account-id based leakage across tenants/providers.
            return Response({"nodes": [], "edges": []})

        nodes: dict[str, dict] = {}
        edges: list[dict] = []
        edge_seen: set[tuple[str, str, str]] = set()
        try:
            with _provider_graph_session(provider, scan_id=scan_id) as session:
                node_query = """
                    MATCH (n)
                    WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
                      AND ($label IS NULL OR any(l IN labels(n) WHERE l = $label))
                    RETURN n
                    LIMIT 4000
                """
                for row in session.run(node_query, account_id=account_id, label=label_filter, update_tag=update_tag):
                    node = row.get("n")
                    if node is None:
                        continue
                    props = _json_safe(dict(node))
                    labels = list(node.labels)
                    node_id = _graph_node_id(props)
                    nodes[node_id] = {
                        "id": node_id,
                        "label": _graph_node_label(props, labels),
                        "type": labels[0] if labels else "Node",
                        "labels": labels,
                        "properties": props,
                    }

                rel_query = """
                    MATCH (n)-[r]->(m)
                    WHERE toInteger(coalesce(r.lastupdated, -1)) = toInteger($update_tag)
                      AND toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
                      AND toInteger(coalesce(m.lastupdated, -1)) = toInteger($update_tag)
                      AND ($label IS NULL OR any(l IN labels(n) WHERE l = $label) OR any(l IN labels(m) WHERE l = $label))
                    RETURN n, r, m
                    LIMIT 8000
                """
                for i, row in enumerate(session.run(rel_query, account_id=account_id, label=label_filter, update_tag=update_tag)):
                    n = row.get("n")
                    m = row.get("m")
                    r = row.get("r")
                    if n is None or m is None or r is None:
                        continue
                    n_props = _json_safe(dict(n))
                    m_props = _json_safe(dict(m))
                    n_labels = list(n.labels)
                    m_labels = list(m.labels)
                    source = _graph_node_id(n_props)
                    target = _graph_node_id(m_props)

                    if source not in nodes:
                        nodes[source] = {
                            "id": source,
                            "label": _graph_node_label(n_props, n_labels),
                            "type": n_labels[0] if n_labels else "Node",
                            "labels": n_labels,
                            "properties": n_props,
                        }
                    if target not in nodes:
                        nodes[target] = {
                            "id": target,
                            "label": _graph_node_label(m_props, m_labels),
                            "type": m_labels[0] if m_labels else "Node",
                            "labels": m_labels,
                            "properties": m_props,
                        }

                    rel_type = str(r.type)
                    edge_key = (source, target, rel_type)
                    if edge_key in edge_seen:
                        continue
                    edge_seen.add(edge_key)
                    edges.append(
                        {
                            "id": f"edge-{i}-{source}-{target}-{rel_type}",
                            "source": source,
                            "target": target,
                            "relationship": rel_type,
                        }
                    )
        except Exception as exc:
            return Response({"nodes": [], "edges": [], "error": str(exc)})

        return Response({"nodes": list(nodes.values()), "edges": edges})


class AttackEngineQueryCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(ATTACK_QUERIES)


class AttackEngineRunAllView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, provider_id: int):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=provider_id, tenant=tenant)
        scan_id = request.data.get("scan_id")
        update_tag = _provider_scan_update_tag(provider, scan_id=scan_id)
        if update_tag is None:
            return Response({"results": []})
        with _provider_graph_session(provider) as session:
            results = run_all_queries(
                provider.aws_account_id,
                neo4j_session=session,
                update_tag=update_tag,
            )
        return Response({"results": results})


class AttackEngineSingleQueryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, provider_id: int, query_id: str):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=provider_id, tenant=tenant)
        scan_id = request.query_params.get("scan_id")
        update_tag = _provider_scan_update_tag(provider, scan_id=scan_id)
        if update_tag is None:
            return Response(
                {
                    "query_id": query_id,
                    "violated": False,
                    "nodes": [],
                    "edges": [],
                    "paths": [],
                }
            )
        with _provider_graph_session(provider) as session:
            result = get_attack_graph(
                query_id,
                provider.aws_account_id,
                neo4j_session=session,
                update_tag=update_tag,
            )
        return Response(result)


# --- Findings (Rule Engine) ---

class ProviderFindingsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, provider_id: int):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=provider_id, tenant=tenant)
        qs = Finding.objects.filter(tenant=tenant, provider=provider)
        status_filter = request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)
        severity_filter = request.query_params.get("severity")
        if severity_filter:
            qs = qs.filter(severity=severity_filter)
        resource_type_filter = request.query_params.get("resource_type")
        if resource_type_filter:
            qs = qs.filter(resource_type=resource_type_filter)

        qs = qs.order_by("-last_seen")

        # Optional: filter by compliance framework/category keyword (CIS/DPDP/RBI/SBE).
        # We match against multiple finding fields so legacy + new rules behave consistently.
        framework_filter = request.query_params.get("framework")
        if framework_filter:
            wanted = framework_filter.strip().upper()

            def _matches_framework(finding) -> bool:
                rule_id = str(finding.rule_id or "").upper()
                raw = finding.raw_finding if isinstance(finding.raw_finding, dict) else {}

                # Strict handling for known framework filters to avoid cross-match noise.
                if wanted in {"CIS", "DPDP", "RBI", "SBE"}:
                    if rule_id.startswith(f"{wanted}-"):
                        return True

                    tokens = set()
                    for item in (finding.compliance_frameworks or []):
                        if isinstance(item, str):
                            upper_item = item.upper()
                            if upper_item.startswith("CIS"):
                                tokens.add("CIS")
                            if upper_item.startswith("DPDP"):
                                tokens.add("DPDP")
                            if upper_item.startswith("RBI"):
                                tokens.add("RBI")
                            if upper_item.startswith("SBE"):
                                tokens.add("SBE")

                    framework_value = raw.get("framework")
                    if isinstance(framework_value, str):
                        fw = framework_value.upper()
                        if fw.startswith("CIS"):
                            tokens.add("CIS")
                        if fw.startswith("DPDP"):
                            tokens.add("DPDP")
                        if fw.startswith("RBI"):
                            tokens.add("RBI")
                        if fw.startswith("SBE"):
                            tokens.add("SBE")

                    for item in (raw.get("compliance") or []):
                        if isinstance(item, str):
                            up = item.upper()
                            if up.startswith("CIS"):
                                tokens.add("CIS")
                            if up.startswith("DPDP"):
                                tokens.add("DPDP")
                            if up.startswith("RBI"):
                                tokens.add("RBI")
                            if up.startswith("SBE"):
                                tokens.add("SBE")

                    return wanted in tokens

                # Generic fallback for non-framework keyword filters.
                fields = [str(x) for x in (finding.compliance_frameworks or [])]
                if raw.get("framework"):
                    fields.append(str(raw.get("framework")))
                if isinstance(raw.get("compliance"), list):
                    fields.extend([str(x) for x in raw.get("compliance") or []])
                if finding.rule_id:
                    fields.append(str(finding.rule_id))
                if finding.rule_name:
                    fields.append(str(finding.rule_name))
                return wanted in " | ".join(fields).upper()

            # Paginate after conversion to list for deterministic Python-side matching.
            qs = [f for f in qs if _matches_framework(f)]

        from rest_framework.pagination import PageNumberPagination
        paginator = PageNumberPagination()
        paginator.page_size = 50
        page = paginator.paginate_queryset(qs, request)
        serializer = FindingSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class ProviderFindingsSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, provider_id: int):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=provider_id, tenant=tenant)
        qs = Finding.objects.filter(tenant=tenant, provider=provider, status="OPEN")
        total_open = qs.count()
        from django.db.models import Count
        by_severity = dict(qs.values("severity").annotate(c=Count("id")).values_list("severity", "c"))
        by_resource_type = dict(qs.values("resource_type").annotate(c=Count("id")).values_list("resource_type", "c"))
        frameworks = {}
        for f in qs.values_list("compliance_frameworks", flat=True):
            if isinstance(f, list):
                for x in f:
                    if isinstance(x, str):
                        frameworks[x] = frameworks.get(x, 0) + 1
        last_run = InventoryRun.objects.filter(provider=provider).order_by("-started_at").first()
        new_this_run = 0
        if last_run:
            new_this_run = Finding.objects.filter(tenant=tenant, provider=provider, inventory_run=last_run).count()
        return Response({
            "total_open": total_open,
            "by_severity": by_severity,
            "by_resource_type": by_resource_type,
            "by_framework": frameworks,
            "new_this_run": new_this_run,
        })


class FindingSuppressView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, id: int):
        tenant = request.user.profile.tenant
        finding = get_object_or_404(Finding, id=id, tenant=tenant)
        finding.status = "SUPPRESSED"
        finding.save(update_fields=["status"])
        return Response(status=status.HTTP_200_OK)


class CustomRuleListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tenant = request.user.profile.tenant
        provider_id = request.query_params.get("provider_id")
        qs = CustomRule.objects.filter(tenant=tenant).order_by("-created_at")
        if provider_id:
            qs = qs.filter(provider_id=provider_id)
        return Response(CustomRuleSerializer(qs, many=True).data)

    def post(self, request):
        tenant = request.user.profile.tenant
        serializer = CustomRuleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(tenant=tenant, created_by=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
