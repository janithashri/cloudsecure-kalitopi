# InventoryRun is registered in providers.admin so it appears under "Providers" in Django admin.

from django.contrib import admin
from .models import ResourceConfig


@admin.register(ResourceConfig)
class ResourceConfigAdmin(admin.ModelAdmin):
    list_display = ["id", "resource_type", "account_id", "region", "arn_short", "last_updated"]
    list_filter = ["resource_type", "account_id"]
    search_fields = ["arn", "account_id", "resource_type"]
    readonly_fields = ["account_id", "arn", "resource_type", "region", "config", "tags", "last_updated"]

    def arn_short(self, obj):
        return obj.arn[:80] + "..." if len(obj.arn) > 80 else obj.arn

    arn_short.short_description = "ARN"
