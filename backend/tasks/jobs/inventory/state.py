from django.db import transaction

from api.models import ResourceStateHash


def load_hashes(account_id: str) -> dict:
    """
    Returns {arn: {'tag_hash': str, 'config_hash': str|None}}
    """
    qs = ResourceStateHash.objects.filter(account_id=account_id)
    return {
        row.arn: {"tag_hash": row.tag_hash, "config_hash": row.config_hash}
        for row in qs
    }


@transaction.atomic
def save_hashes(account_id: str, hashes: dict):
    """
    Upsert all hashes for account. Runs in a transaction — either all
    hashes update or none do. Prevents partial state on task failure.
    """
    for arn, hash_data in hashes.items():
        ResourceStateHash.objects.update_or_create(
            account_id=account_id,
            arn=arn,
            defaults={
                "tag_hash": hash_data["tag_hash"],
                "config_hash": hash_data.get("config_hash"),
            },
        )
    ResourceStateHash.objects.filter(account_id=account_id).exclude(
        arn__in=list(hashes.keys())
    ).delete()
