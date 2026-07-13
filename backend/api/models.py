import uuid

from django.db import models


class InventoryRun(models.Model):
    STATE_CHOICES = [
        ("running", "Running"),
        ("completed", "Completed"),
        ("partial", "Partial"),
        ("failed", "Failed"),
    ]
    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE)
    provider = models.ForeignKey("providers.Provider", on_delete=models.CASCADE, related_name="inventory_runs")
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default="running")
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    stats = models.JSONField(default=dict)

    class Meta:
        ordering = ["-started_at"]


class ResourceStateHash(models.Model):
    account_id = models.CharField(max_length=64)
    arn = models.TextField()
    tag_hash = models.CharField(max_length=64)
    config_hash = models.CharField(max_length=64, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [["account_id", "arn"]]
        indexes = [models.Index(fields=["account_id"])]


class ResourceConfig(models.Model):
    account_id = models.CharField(max_length=64)
    arn = models.TextField()
    resource_type = models.CharField(max_length=128)
    region = models.CharField(max_length=64)
    config = models.JSONField()
    tags = models.JSONField(default=dict)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [["account_id", "arn"]]
        indexes = [
            models.Index(fields=["account_id", "resource_type"]),
            models.Index(fields=["account_id"]),
        ]

    def __str__(self):
        return f"{self.resource_type} | {self.arn}"


class Finding(models.Model):
    SEVERITY_CHOICES = [
        ("CRITICAL", "Critical"),
        ("HIGH", "High"),
        ("MEDIUM", "Medium"),
        ("LOW", "Low"),
        ("INFO", "Info"),
    ]
    STATUS_CHOICES = [
        ("OPEN", "Open"),
        ("SUPPRESSED", "Suppressed"),
        ("RESOLVED", "Resolved"),
    ]
    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE)
    provider = models.ForeignKey("providers.Provider", on_delete=models.CASCADE)
    inventory_run = models.ForeignKey(
        InventoryRun, on_delete=models.CASCADE, related_name="findings"
    )
    arn = models.TextField()
    account_id = models.CharField(max_length=64)
    resource_type = models.CharField(max_length=128)
    region = models.CharField(max_length=64)
    rule_id = models.CharField(max_length=128)
    rule_name = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="OPEN"
    )
    compliance_frameworks = models.JSONField(default=list)
    remediation_steps = models.TextField(blank=True)
    raw_finding = models.JSONField(default=dict)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [["arn", "rule_id"]]
        indexes = [
            models.Index(fields=["tenant", "provider", "status"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["account_id"]),
        ]

    def __str__(self):
        return f"{self.rule_id} | {self.arn[:80]}"


class CustomRule(models.Model):
    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE)
    provider = models.ForeignKey(
        "providers.Provider",
        on_delete=models.CASCADE,
        related_name="custom_rules",
        null=True,
        blank=True,
    )
    name = models.CharField(max_length=150)
    resource_type = models.CharField(max_length=128)
    rule_id = models.CharField(max_length=128)
    severity = models.CharField(max_length=20, choices=Finding.SEVERITY_CHOICES, default="MEDIUM")
    compliance_frameworks = models.JSONField(default=list)
    description = models.TextField(blank=True)
    rego_policy = models.TextField()
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [["tenant", "rule_id"]]
        indexes = [
            models.Index(fields=["tenant", "enabled"]),
            models.Index(fields=["resource_type"]),
        ]

    def __str__(self):
        return f"{self.rule_id} ({self.resource_type})"


class ConfigChangeCursor(models.Model):
    """
    Tracks last successful AWS Config drift polling watermark per account/region.
    """

    account_id = models.CharField(max_length=64)
    region = models.CharField(max_length=32, default="ap-south-1")
    last_polled_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [["account_id", "region"]]
        indexes = [
            models.Index(fields=["account_id", "region"]),
        ]

    def __str__(self):
        return f"{self.account_id}@{self.region}"


class DeepScanStateChoices(models.TextChoices):
    SCHEDULED = "SCHEDULED", "Scheduled"
    EXECUTING = "EXECUTING", "Executing"
    COMPLETED = "COMPLETED", "Completed"
    FAILED = "FAILED", "Failed"


class DeepScan(models.Model):
    class Meta:
        db_table = "deep_scans"
        ordering = ["-started_at"]
        indexes = [
            models.Index(fields=["scan_id"]),
            models.Index(fields=["provider_id", "state"]),
            models.Index(fields=["tenant_id", "state"]),
        ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE)
    provider = models.ForeignKey(
        "providers.Provider", on_delete=models.CASCADE, related_name="deep_scans"
    )
    state = models.CharField(
        max_length=20,
        choices=DeepScanStateChoices.choices,
        default=DeepScanStateChoices.SCHEDULED,
        db_index=True,
    )
    progress = models.IntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.IntegerField(null=True, blank=True)
    task_id = models.CharField(max_length=255, null=True, blank=True)
    update_tag = models.BigIntegerField(null=True, blank=True)
    graph_database = models.CharField(max_length=255, null=True, blank=True)
    is_graph_database_deleted = models.BooleanField(default=False)
    ingestion_exceptions = models.JSONField(null=True, blank=True, default=dict)

    def __str__(self):
        return f"DeepScan {self.scan_id} (provider={self.provider_id}, state={self.state})"

    @property
    def is_terminal(self):
        return self.state in (DeepScanStateChoices.COMPLETED, DeepScanStateChoices.FAILED)
