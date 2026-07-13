"""
Deep Scan REST API views.
"""

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.models import DeepScan, DeepScanStateChoices
from providers.models import Provider


class DeepScanListView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        tenant = request.user.profile.tenant
        provider_id = request.data.get("provider_id")
        if not provider_id:
            return Response({"error": "provider_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        provider = get_object_or_404(Provider, id=provider_id, tenant=tenant)
        scan = DeepScan.objects.create(
            tenant=tenant,
            provider=provider,
            state=DeepScanStateChoices.SCHEDULED,
        )

        from tasks.jobs.deep_scan.scan import run

        task = run.apply_async(
            kwargs={
                "tenant_id": str(tenant.id),
                "scan_id": str(scan.scan_id),
                "provider_id": provider.id,
            },
            queue="deep_scan",
        )
        scan.task_id = task.id
        scan.save(update_fields=["task_id"])
        return Response({"scan_id": str(scan.scan_id), "state": scan.state}, status=status.HTTP_201_CREATED)

    def get(self, request):
        tenant = request.user.profile.tenant
        provider_id = request.query_params.get("provider_id")
        limit = int(request.query_params.get("limit", 20))
        if not provider_id:
            return Response({"error": "provider_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        scans = (
            DeepScan.objects.filter(provider_id=provider_id, tenant=tenant)
            .order_by("-started_at")[:limit]
            .values(
                "scan_id",
                "state",
                "progress",
                "started_at",
                "completed_at",
                "duration",
                "update_tag",
                "ingestion_exceptions",
            )
        )
        scans_list = []
        for scan in scans:
            scan["scan_id"] = str(scan["scan_id"])
            scan["started_at"] = scan["started_at"].isoformat() if scan["started_at"] else None
            scan["completed_at"] = scan["completed_at"].isoformat() if scan["completed_at"] else None
            scans_list.append(scan)
        return Response({"scans": scans_list})


class DeepScanDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id: str):
        tenant = request.user.profile.tenant
        scan = get_object_or_404(DeepScan, scan_id=scan_id, tenant=tenant)
        return Response(
            {
                "scan_id": str(scan.scan_id),
                "state": scan.state,
                "progress": scan.progress,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration": scan.duration,
                "update_tag": scan.update_tag,
                "graph_database": scan.graph_database,
                "ingestion_exceptions": scan.ingestion_exceptions or {},
                "is_graph_db_deleted": scan.is_graph_database_deleted,
            }
        )

    def delete(self, request, scan_id: str):
        tenant = request.user.profile.tenant
        scan = get_object_or_404(DeepScan, scan_id=scan_id, tenant=tenant)
        if scan.state in (DeepScanStateChoices.COMPLETED, DeepScanStateChoices.FAILED):
            return Response({"error": "Scan is already in a terminal state"}, status=status.HTTP_409_CONFLICT)

        if scan.task_id:
            from cloudsecure.celery import app as celery_app

            celery_app.control.revoke(scan.task_id, terminate=True, signal="SIGTERM")

        scan.state = DeepScanStateChoices.FAILED
        scan.ingestion_exceptions = {"global_error": "Cancelled by user"}
        scan.save(update_fields=["state", "ingestion_exceptions"])
        return Response({"cancelled": True})
