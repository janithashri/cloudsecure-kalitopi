import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0001_initial"),
        ("providers", "0001_initial"),
        ("api", "0006_configchangecursor"),
    ]

    operations = [
        migrations.CreateModel(
            name="DeepScan",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("scan_id", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("SCHEDULED", "Scheduled"),
                            ("EXECUTING", "Executing"),
                            ("COMPLETED", "Completed"),
                            ("FAILED", "Failed"),
                        ],
                        db_index=True,
                        default="SCHEDULED",
                        max_length=20,
                    ),
                ),
                ("progress", models.IntegerField(default=0)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("duration", models.IntegerField(blank=True, null=True)),
                ("task_id", models.CharField(blank=True, max_length=255, null=True)),
                ("update_tag", models.BigIntegerField(blank=True, null=True)),
                ("graph_database", models.CharField(blank=True, max_length=255, null=True)),
                ("is_graph_database_deleted", models.BooleanField(default=False)),
                ("ingestion_exceptions", models.JSONField(blank=True, default=dict, null=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="accounts.tenant")),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="deep_scans",
                        to="providers.provider",
                    ),
                ),
            ],
            options={
                "db_table": "deep_scans",
                "ordering": ["-started_at"],
                "indexes": [
                    models.Index(fields=["scan_id"], name="api_deepsca_scan_id_idx"),
                    models.Index(fields=["provider_id", "state"], name="api_deepsca_provide_idx"),
                    models.Index(fields=["tenant_id", "state"], name="api_deepsca_tenant__idx"),
                ],
            },
        ),
    ]
