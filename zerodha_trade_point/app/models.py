"""
Definition of models.
"""

from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
import uuid


def generate_kite_user_identifier():
    """Returns a stable random ID shown to app users for each stored Kite user."""
    return 'ZK{0}'.format(uuid.uuid4().hex[:12].upper())

class Profile(models.Model):
    """Role for a Django login user: manage only own accounts or all."""
    SELF_ONLY = 'self_only'
    ADMIN_ONLY = 'admin_only'
    TRADER_ALL = 'trader_all'
    ROLE_CHOICES = (
        (SELF_ONLY, 'Self only'),
        (ADMIN_ONLY, 'Admin only'),
        (TRADER_ALL, 'Trader all'),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=SELF_ONLY)

    def __str__(self):
        return '{0} ({1})'.format(self.user.username, self.role)


@receiver(post_save, sender=User)
def ensure_profile(sender, instance, created, **kwargs):
    """Auto-create a default self_only profile for every new login user."""
    if created:
        Profile.objects.get_or_create(user=instance, defaults={'role': Profile.SELF_ONLY})

class KiteUser(models.Model):
    """A Zerodha Kite Connect user whose API credentials are persisted."""
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='kite_users', null=True)
    zk_user_id = models.CharField(max_length=24, unique=True, default=generate_kite_user_identifier)
    api_key = models.CharField(max_length=64, unique=True)
    api_secret = models.CharField(max_length=128, blank=True, default='')
    access_token = models.CharField(max_length=128, blank=True, default='')
    refresh_token = models.CharField(max_length=128, blank=True, default='')
    manual_token = models.BooleanField(default=False)
    user_id = models.CharField(max_length=32, blank=True, default='')
    user_name = models.CharField(max_length=128, blank=True, default='')
    zerodha_password = models.CharField(max_length=128, blank=True, default='')
    zerodha_totp_key = models.CharField(max_length=64, blank=True, default='')
    automate = models.PositiveSmallIntegerField(default=0)
    email = models.EmailField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return '{0} ({1})'.format(self.zk_user_id, self.user_name or self.user_id or self.api_key)
