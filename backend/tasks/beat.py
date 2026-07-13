import json

from django_celery_beat.models import IntervalSchedule, PeriodicTask


def schedule_inventory_pull(provider):
    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=30,
        period=IntervalSchedule.MINUTES,
    )
    PeriodicTask.objects.update_or_create(
        name=f"inventory-pull-provider-{provider.id}",
        defaults={
            "task": "tasks.tasks.perform_inventory_pull_task",
            "interval": schedule,
            "kwargs": json.dumps(
                {
                    "tenant_id": provider.tenant_id,
                    "provider_id": provider.id,
                }
            ),
            "enabled": True,
            "one_off": False,
        },
    )


def disable_inventory_pull(provider):
    PeriodicTask.objects.filter(
        name=f"inventory-pull-provider-{provider.id}",
    ).update(enabled=False)
