from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("providers", "0001_initial"),
        ("api", "0004_finding"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="CustomRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=150)),
                ("resource_type", models.CharField(max_length=128)),
                ("rule_id", models.CharField(max_length=128)),
                (
                    "severity",
                    models.CharField(
                        choices=[("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low"), ("INFO", "Info")],
                        default="MEDIUM",
                        max_length=20,
                    ),
                ),
                ("compliance_frameworks", models.JSONField(default=list)),
                ("description", models.TextField(blank=True)),
                ("rego_policy", models.TextField()),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
                ),
                ("provider", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="custom_rules", to="providers.provider")),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="accounts.tenant")),
            ],
            options={
                "indexes": [models.Index(fields=["tenant", "enabled"], name="api_customru_tenant__7ea357_idx"), models.Index(fields=["resource_type"], name="api_customru_resourc_453f45_idx")],
                "unique_together": {("tenant", "rule_id")},
            },
        ),
    ]
