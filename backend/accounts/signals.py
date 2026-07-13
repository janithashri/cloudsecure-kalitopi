from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile, Tenant


@receiver(post_save, sender=User)
def create_profile_and_tenant(sender, instance, created, **kwargs):
    if created:
        tenant = Tenant.objects.create(name=f"Tenant for {instance.email or instance.username}")
        UserProfile.objects.create(user=instance, tenant=tenant)
