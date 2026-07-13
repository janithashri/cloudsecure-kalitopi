"""
List resource types and ARNs from ResourceStateHash (from inventory runs).
Usage:
  python manage.py list_inventory_resource_types
  python manage.py list_inventory_resource_types --filter iam,security-group
"""
from django.core.management.base import BaseCommand

from api.models import ResourceStateHash


def arn_to_type_key(arn: str) -> str:
    """Derive a type key from ARN (e.g. arn:aws:iam::123:role/X -> iam/role)."""
    parts = arn.split(":")
    if len(parts) >= 6:
        # service is often parts[2], resource part is parts[5] e.g. "role/MyRole" or "security-group/sg-xxx"
        service = parts[2].lower()
        resource_part = parts[5].split("/")[0] if len(parts) > 5 else ""
        return f"{service}::{resource_part}" if resource_part else service
    return "unknown"


class Command(BaseCommand):
    help = "List resource types and ARNs from inventory (ResourceStateHash)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--filter",
            type=str,
            default="",
            help="Comma-separated substrings to filter ARNs (e.g. iam,security-group). Print only ARNs containing any of these.",
        )

    def handle(self, *args, **options):
        rows = ResourceStateHash.objects.all().order_by("arn")
        filter_substrings = [s.strip().lower() for s in (options["filter"] or "").split(",") if s.strip()]

        type_to_arns = {}
        for r in rows:
            type_key = arn_to_type_key(r.arn)
            type_to_arns.setdefault(type_key, []).append(r.arn)

        self.stdout.write("Resource types (from ARNs in ResourceStateHash):")
        for t in sorted(type_to_arns.keys()):
            count = len(type_to_arns[t])
            self.stdout.write(f"  {t}: {count}")

        if filter_substrings:
            self.stdout.write("")
            self.stdout.write(f"ARNs containing any of {filter_substrings}:")
            for r in rows:
                arn_lower = r.arn.lower()
                if any(sub in arn_lower for sub in filter_substrings):
                    self.stdout.write(f"  {r.arn}")
        else:
            self.stdout.write("")
            self.stdout.write("Sample ARN per type (first only):")
            for t in sorted(type_to_arns.keys()):
                self.stdout.write(f"  {t}: {type_to_arns[t][0]}")
