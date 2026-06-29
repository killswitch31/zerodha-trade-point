"""
Template context processors: expose the signed-in user's role app-wide.
"""

from app.models import Profile


def user_role(request):
    """Adds the current user's access level to every template context.

    'app_is_admin' is True for superusers or admin_only profiles (gates user
    management); 'app_can_configure' is True for everyone except trader_all
    (gates account add/delete); 'app_can_trade_all' is True for admins and
    trader_all (gates the trade owner dropdown); 'app_role'/'app_role_css'
    drive the navbar badge.
    """
    user = getattr(request, 'user', None)
    if not user or not user.is_authenticated:
        return {}
    if user.is_superuser:
        return {
            'app_is_admin': True,
            'app_can_configure': True,
            'app_can_trade_all': True,
            'app_role': 'Admin',
            'app_role_css': 'label-warning',
        }
    profile = getattr(user, 'profile', None)
    role = getattr(profile, 'role', Profile.SELF_ONLY)
    is_admin = role == Profile.ADMIN_ONLY
    is_trader_all = role == Profile.TRADER_ALL
    if is_admin:
        label, css = 'Admin', 'label-warning'
    elif is_trader_all:
        label, css = 'Trader all', 'label-success'
    else:
        label, css = 'Self only', 'label-info'
    return {
        'app_is_admin': is_admin,
        'app_can_configure': not is_trader_all,
        'app_can_trade_all': is_admin or is_trader_all,
        'app_role': label,
        'app_role_css': css,
    }
