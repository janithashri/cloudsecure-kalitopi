from django.core.management.base import BaseCommand, CommandError

from providers.models import Provider
from tasks.jobs.inventory.config import get_client


class Command(BaseCommand):
    help = "Validate AWS Config access using provider assumed role."

    def add_arguments(self, parser):
        parser.add_argument("--provider-id", type=int, required=True, help="Provider ID")
        parser.add_argument(
            "--region",
            type=str,
            default="ap-south-1",
            help="AWS Config region (default: ap-south-1)",
        )

    def handle(self, *args, **options):
        provider_id = options["provider_id"]
        region = options["region"]

        provider = Provider.objects.filter(id=provider_id).first()
        if not provider:
            raise CommandError(f"Provider {provider_id} not found")

        account_id = provider.aws_account_id
        role_name = provider.inventory_role_name
        self.stdout.write(
            self.style.NOTICE(
                f"Checking AWS Config access for account={account_id}, role={role_name}, region={region}"
            )
        )

        try:
            client = get_client(account_id, role_name, "config", region)
            status = client.describe_configuration_recorder_status()
            recorders = status.get("ConfigurationRecordersStatus") or []
            if not recorders:
                self.stdout.write(
                    self.style.WARNING(
                        "AWS Config client is reachable, but no configuration recorder status found."
                    )
                )
            else:
                names = [r.get("name") for r in recorders if isinstance(r, dict)]
                self.stdout.write(self.style.SUCCESS(f"AWS Config reachable. Recorders: {names}"))
        except Exception as e:
            raise CommandError(f"AWS Config validation failed: {e}")
