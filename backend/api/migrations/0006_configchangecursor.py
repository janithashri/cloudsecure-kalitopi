from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0005_customrule"),
    ]

    operations = [
        migrations.CreateModel(
            name="ConfigChangeCursor",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("account_id", models.CharField(max_length=64)),
                ("region", models.CharField(default="ap-south-1", max_length=32)),
                ("last_polled_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "indexes": [models.Index(fields=["account_id", "region"], name="api_configch_account_9fbc04_idx")],
                "unique_together": {("account_id", "region")},
            },
        ),
    ]
