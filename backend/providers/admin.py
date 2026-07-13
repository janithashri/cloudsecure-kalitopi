from django.contrib import admin
from api.models import InventoryRun
from .models import Provider


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    list_display = ["name", "aws_account_id", "connection_verified", "active", "tenant"]
    list_filter = ["active", "connection_verified"]


@admin.register(InventoryRun)
class InventoryRunAdmin(admin.ModelAdmin):
    list_display = ["id", "provider", "state", "started_at", "completed_at"]
    list_filter = ["state"]
    readonly_fields = ["tenant", "provider", "state", "started_at", "completed_at", "stats"]
    search_fields = ["provider__name", "provider__aws_account_id"]

    def has_add_permission(self, request):
        return False
