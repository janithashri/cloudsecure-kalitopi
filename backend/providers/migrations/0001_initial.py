from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Provider",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255)),
                ("aws_account_id", models.CharField(max_length=12)),
                ("inventory_role_name", models.CharField(max_length=255)),
                ("active", models.BooleanField(default=True)),
                ("connection_verified", models.BooleanField(default=False)),
                ("last_connection_test", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="providers",
                        to="accounts.tenant",
                    ),
                ),
            ],
        ),
    ]

