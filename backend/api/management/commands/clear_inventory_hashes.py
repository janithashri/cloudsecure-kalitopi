"""
Delete stored inventory state (ResourceStateHash) so the next scan treats all resources as new.
Usage:
  python manage.py clear_inventory_hashes                    # all accounts
  python manage.py clear_inventory_hashes --account 123456789012   # one account
"""
from django.core.management.base import BaseCommand

from api.models import ResourceStateHash


class Command(BaseCommand):
    help = "Delete ResourceStateHash rows so the next inventory run sees all resources as new."

    def add_arguments(self, parser):
        parser.add_argument(
            "--account",
            type=str,
            default="",
            help="AWS account ID. If omitted, deletes hashes for all accounts.",
        )

    def handle(self, *args, **options):
        account = (options["account"] or "").strip()
        qs = ResourceStateHash.objects.all()
        if account:
            qs = qs.filter(account_id=account)
        count = qs.count()
        qs.delete()
        if account:
            self.stdout.write(self.style.SUCCESS(f"Deleted {count} hashes for account {account}."))
        else:
            self.stdout.write(self.style.SUCCESS(f"Deleted {count} hashes (all accounts)."))
        self.stdout.write("Next scan will treat all resources as new (delta = full).")
