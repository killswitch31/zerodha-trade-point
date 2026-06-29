"""Backfill a default self_only Profile for any existing users without one."""

from django.db import migrations


def create_missing_profiles(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    Profile = apps.get_model('app', 'Profile')
    for user in User.objects.all():
        Profile.objects.get_or_create(user=user, defaults={'role': 'self_only'})


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_kiteuser_owner_profile'),
    ]

    operations = [
        migrations.RunPython(create_missing_profiles, noop),
    ]
