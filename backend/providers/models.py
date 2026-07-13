from django.db import models
from accounts.models import Tenant


class Provider(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="providers")
    name = models.CharField(max_length=255)
    aws_account_id = models.CharField(max_length=12)
    inventory_role_name = models.CharField(max_length=255)
    active = models.BooleanField(default=True)
    connection_verified = models.BooleanField(default=False)
    last_connection_test = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
