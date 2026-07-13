from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="ResourceConfig",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("account_id", models.CharField(max_length=64)),
                ("arn", models.TextField()),
                ("resource_type", models.CharField(max_length=128)),
                ("region", models.CharField(max_length=64)),
                ("config", models.JSONField()),
                ("tags", models.JSONField(default=dict)),
                ("last_updated", models.DateTimeField(auto_now=True)),
            ],
            options={
                "indexes": [
                    models.Index(fields=["account_id", "resource_type"], name="api_resourc_account_resou_idx"),
                    models.Index(fields=["account_id"], name="api_resourc_account_id_idx"),
                ],
                "unique_together": {("account_id", "arn")},
            },
        ),
    ]
