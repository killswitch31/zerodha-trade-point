"""
Admin registrations: assign roles to login users; inspect Kite accounts.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from app.models import Profile, KiteUser


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Role'


class UserWithRoleAdmin(UserAdmin):
    inlines = [ProfileInline]
    list_display = ('username', 'email', 'is_staff', 'is_superuser', 'get_role')

    def get_role(self, obj):
        return getattr(getattr(obj, 'profile', None), 'role', '-')
    get_role.short_description = 'Role'


@admin.register(KiteUser)
class KiteUserAdmin(admin.ModelAdmin):
    list_display = ('user_name', 'user_id', 'api_key', 'owner', 'manual_token')
    search_fields = ('user_name', 'user_id', 'api_key')


admin.site.unregister(User)
admin.site.register(User, UserWithRoleAdmin)
