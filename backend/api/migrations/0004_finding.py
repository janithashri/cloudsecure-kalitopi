from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0001_initial"),
        ("providers", "0001_initial"),
        ("api", "0003_resourceconfig"),
    ]

    operations = [
        migrations.CreateModel(
            name="Finding",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("arn", models.TextField()),
                ("account_id", models.CharField(max_length=64)),
                ("resource_type", models.CharField(max_length=128)),
                ("region", models.CharField(max_length=64)),
                ("rule_id", models.CharField(max_length=128)),
                ("rule_name", models.CharField(max_length=255)),
                ("severity", models.CharField(choices=[("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low"), ("INFO", "Info")], max_length=20)),
                ("status", models.CharField(choices=[("OPEN", "Open"), ("SUPPRESSED", "Suppressed"), ("RESOLVED", "Resolved")], default="OPEN", max_length=20)),
                ("compliance_frameworks", models.JSONField(default=list)),
                ("remediation_steps", models.TextField(blank=True)),
                ("raw_finding", models.JSONField(default=dict)),
                ("first_seen", models.DateTimeField(auto_now_add=True)),
                ("last_seen", models.DateTimeField(auto_now=True)),
                ("inventory_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="findings", to="api.inventoryrun")),
                ("provider", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="providers.provider")),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="accounts.tenant")),
            ],
            options={
                "indexes": [
                    models.Index(fields=["tenant", "provider", "status"], name="api_finding_tenant_provider_status_idx"),
                    models.Index(fields=["severity"], name="api_finding_severity_idx"),
                    models.Index(fields=["account_id"], name="api_finding_account_id_idx"),
                ],
                "unique_together": {("arn", "rule_id")},
            },
        ),
    ]
