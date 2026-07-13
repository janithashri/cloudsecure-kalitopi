from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
        ("providers", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="InventoryRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("state", models.CharField(choices=[("running", "Running"), ("completed", "Completed"), ("partial", "Partial"), ("failed", "Failed")], default="running", max_length=20)),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("stats", models.JSONField(default=dict)),
                ("provider", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="inventory_runs", to="providers.provider")),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="accounts.tenant")),
            ],
            options={
                "ordering": ["-started_at"],
            },
        ),
        migrations.CreateModel(
            name="ResourceStateHash",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("account_id", models.CharField(max_length=64)),
                ("arn", models.TextField()),
                ("tag_hash", models.CharField(max_length=64)),
                ("config_hash", models.CharField(blank=True, max_length=64, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "indexes": [
                    models.Index(fields=["account_id"], name="api_resourc_account_8f0b0d_idx"),
                ],
                "unique_together": {("account_id", "arn")},
            },
        ),
    ]
