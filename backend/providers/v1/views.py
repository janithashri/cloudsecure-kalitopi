import boto3
from botocore.exceptions import ClientError
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.models import InventoryRun
from api.serializers import InventoryRunSerializer
from providers.models import Provider
from providers.serializers import ProviderSerializer
from tasks.beat import disable_inventory_pull, schedule_inventory_pull
from tasks.tasks import perform_inventory_pull_task


class ProviderListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tenant = request.user.profile.tenant
        providers = Provider.objects.filter(tenant=tenant)
        serializer = ProviderSerializer(providers, many=True)
        return Response(serializer.data)

    def post(self, request):
        tenant = request.user.profile.tenant
        serializer = ProviderSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(tenant=tenant)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ProviderDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_provider(self, request, pk):
        tenant = request.user.profile.tenant
        return get_object_or_404(Provider, id=pk, tenant=tenant)

    def patch(self, request, pk):
        provider = self.get_provider(request, pk)
        serializer = ProviderSerializer(provider, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request, pk):
        provider = self.get_provider(request, pk)
        disable_inventory_pull(provider)
        provider.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class TestConnectionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=pk, tenant=tenant)
        role_arn = f"arn:aws:iam::{provider.aws_account_id}:role/{provider.inventory_role_name}"
        try:
            sts = boto3.client("sts")
            assumed = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="CloudSecureConnectionTest",
                DurationSeconds=900,
            )
            provider.connection_verified = True
            provider.last_connection_test = timezone.now()
            provider.save(update_fields=["connection_verified", "last_connection_test", "updated_at"])
            schedule_inventory_pull(provider)
            return Response({
                "status": "success",
                "account_id": provider.aws_account_id,
                "assumed_role_arn": assumed["AssumedRoleUser"]["Arn"],
            })
        except ClientError as e:
            provider.connection_verified = False
            provider.save(update_fields=["connection_verified", "updated_at"])
            msg = e.response.get("Error", {}).get("Message", str(e))
            return Response(
                {"status": "error", "message": msg},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            provider.connection_verified = False
            provider.save(update_fields=["connection_verified", "updated_at"])
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )


class InventoryRunListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=pk, tenant=tenant)
        runs = InventoryRun.objects.filter(provider=provider).order_by("-started_at")[:10]
        serializer = InventoryRunSerializer(runs, many=True)
        data = serializer.data
        # Backward-compatible: keep list response shape, but ensure drift signal key
        # is always present in run stats for easier frontend display/debugging.
        for item in data:
            stats = item.get("stats") or {}
            if "config_changed_signals" not in stats:
                stats["config_changed_signals"] = 0
            item["stats"] = stats
        return Response(data)


class InventoryPullView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        tenant = request.user.profile.tenant
        provider = get_object_or_404(Provider, id=pk, tenant=tenant)

        if InventoryRun.objects.filter(provider=provider, state="running").exists():
            return Response(
                {"detail": "Inventory pull already in progress"},
                status=status.HTTP_409_CONFLICT,
            )

        task = perform_inventory_pull_task.delay(tenant.id, provider.id)
        return Response(
            {"task_id": task.id, "status": "queued"},
            status=status.HTTP_202_ACCEPTED,
        )
