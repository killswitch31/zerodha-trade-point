"""
Definition of views.
"""

import time
import requests
import pyotp
import json
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpRequest, JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.utils.http import urlencode
from urllib.parse import parse_qs, urlparse
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from kiteconnect import KiteConnect
from kiteconnect.exceptions import KiteException, TokenException
from app.forms import AddUserForm, ManageZkUserForm, EditAppUserForm, EditKiteCredentialsForm
from app.models import KiteUser, Profile

# Per-process cache of instruments per exchange: {exchange: (timestamp, list)}.
_INSTRUMENTS_CACHE = {}
_INSTRUMENTS_TTL = 60 * 60  # 1 hour

# Add/Delete user management is restricted to superusers.
superuser_required = user_passes_test(lambda u: u.is_superuser, login_url='login')


def is_admin(user):
    """True if the user is an admin_only role holder or a superuser."""
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.role == 'admin_only')


def can_trade_all(user):
    """True if the user may view/act on ALL accounts on the trade dashboard.

    Superusers, admin_only and trader_all roles all manage every account's
    trading; only self_only is restricted to their own accounts.
    """
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.role in ('admin_only', 'trader_all'))


def can_configure_accounts(user):
    """True if the user may add/modify/delete app accounts.

    Everyone except the trade-only role (trader_all) can configure accounts;
    self_only manages just their own, admins manage all.
    """
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    return not (profile and profile.role == 'trader_all')


# Managing app login users is restricted to admin_only role holders / superusers.
admin_required = user_passes_test(is_admin, login_url='login')

# Configuring accounts (add/re-auth/delete) is blocked for the trade-only role.
account_config_required = user_passes_test(can_configure_accounts, login_url='login')

@login_required(login_url='login')
def home(request):
    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/index.html',
        {
            'title':'Home Page',
            'year':datetime.now().year,
        }
    )


def _make_kite(api_key, access_token=None):
    """Creates a KiteConnect client, optionally with an access token set."""
    kite = KiteConnect(api_key=api_key)
    if access_token:
        kite.set_access_token(access_token)
    return kite


def _persist_token_data(user, data):
    """Persists token/user fields returned by generate_session/renew APIs."""
    changed = []
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')
    if access_token and access_token != user.access_token:
        user.access_token = access_token
        changed.append('access_token')
    if refresh_token and refresh_token != user.refresh_token:
        user.refresh_token = refresh_token
        changed.append('refresh_token')
    # user/profile returns user_name and user_id; both are kept fresh from API.
    profile_source = data
    if 'user_name' not in profile_source and 'data' in profile_source and isinstance(profile_source.get('data'), dict):
        profile_source = profile_source.get('data')
    for field in ('user_id', 'user_name', 'email'):
        if field in profile_source and profile_source.get(field) and profile_source.get(field) != getattr(user, field):
            setattr(user, field, profile_source.get(field))
            changed.append(field)
    if changed:
        user.save(update_fields=changed)


def _renew_access_token(user):
    """Renews access_token using stored refresh_token/api_secret."""
    if not user.refresh_token or not user.api_secret:
        return False
    try:
        data = _make_kite(user.api_key).renew_access_token(user.refresh_token, api_secret=user.api_secret)
        _persist_token_data(user, data)
        return bool(user.access_token)
    except KiteException:
        return False


def _call_with_token_renewal(user, operation):
    """Runs an API call and retries once after refresh-token renewal."""
    kite = _make_kite(user.api_key, user.access_token)
    try:
        return operation(kite)
    except TokenException:
        if not _renew_access_token(user):
            raise
        return operation(_make_kite(user.api_key, user.access_token))


def _auth_status(user):
    """Probes the stored token: 'active', 'expired' (token invalid), or 'error'."""
    if not user.access_token:
        return 'none'
    try:
        _call_with_token_renewal(user, lambda kite: kite.profile())
        return 'active'
    except TokenException:
        return 'expired'
    except KiteException:
        return 'error'


def _status_presentation(status):
    """Maps an auth status to a simple label + Bootstrap CSS class.

    Per spec, the token is shown either as 'Active' or
    'Needs reauthentication' wherever a live status is displayed.
    """
    if status == 'active':
        return {'label': 'Active', 'css': 'label-success'}
    return {'label': 'Needs Authentication', 'css': 'label-danger'}


def _user_rows(request_user, owner_filter=''):
    """Builds stored users (scoped by role) with their auth status.

    Users who can trade all accounts may pass owner_filter (an owner username)
    to view a single user's accounts; self_only is restricted to their own.
    """
    qs = KiteUser.objects.select_related('owner').order_by('user_name', 'api_key')
    if can_trade_all(request_user):
        if owner_filter:
            qs = qs.filter(owner__username=owner_filter)
    else:
        qs = qs.filter(owner=request_user)
    rows = []
    for u in qs:
        status = _auth_status(u)
        checked_at = timezone.localtime(timezone.now())
        rows.append({
            'user': u,
            'status': status,
            'presentation': _status_presentation(status),
            'checked_at': checked_at,
        })
    return rows


def _sync_profile_from_kite(user):
    """Fetches /user/profile through SDK and refreshes mapped DB fields."""
    profile = _call_with_token_renewal(user, lambda kite: kite.profile())
    if isinstance(profile, dict):
        _persist_token_data(user, profile)
    return profile


def _automated_kite_login(user):
    """Performs non-interactive Zerodha login + 2FA flow and stores new token."""
    if not (user.automate and user.zerodha_password and user.zerodha_totp_key and user.user_id):
        raise ValueError('Automation requires user ID, password and TOTP key.')
    session = requests.Session()
    login_url = 'https://kite.trade/connect/login?v=3&api_key={0}'.format(user.api_key)
    initial_response = session.get(login_url, timeout=20)
    login_page_url = initial_response.url
    login_response = session.post(
        'https://kite.zerodha.com/api/login',
        data={'user_id': user.user_id, 'password': user.zerodha_password},
        timeout=20,
    )
    login_payload = json.loads(login_response.content)
    request_id = ((login_payload.get('data') or {}).get('request_id'))
    if not request_id:
        raise ValueError('Login failed while submitting Zerodha credentials.')
    current_totp = pyotp.TOTP(user.zerodha_totp_key).now()
    twofa_response = session.post(
        'https://kite.zerodha.com/api/twofa',
        data={
            'user_id': user.user_id,
            'request_id': request_id,
            'twofa_value': current_totp,
        },
        timeout=20,
    )
    twofa_payload = twofa_response.json()
    if twofa_payload.get('status') != 'success':
        raise ValueError('2FA failed while automating Zerodha login.')
    final_response = session.get(login_page_url, allow_redirects=True, timeout=20)
    if 'request_token' not in final_response.url:
        raise ValueError('Unable to obtain request token from Zerodha redirect URL.')
    request_token = parse_qs(urlparse(final_response.url).query)['request_token'][0]
    kite = _make_kite(user.api_key)
    session_data = kite.generate_session(request_token, api_secret=user.api_secret)
    _persist_token_data(user, session_data)
    _sync_profile_from_kite(user)


def _start_reauthentication(request, user):
    """Starts manual OAuth or executes automated auth depending on the user mode."""
    if user.automate == 1:
        _automated_kite_login(user)
        return None
    request.session['pending_zk_user_id'] = user.zk_user_id
    return _make_kite(user.api_key).login_url()


@admin_required
def managezkusers(request):
    """Admin-only: provision and manage app login users, and inspect all Kite accounts."""
    assert isinstance(request, HttpRequest)
    message = None
    message_type = None
    
    if request.method == 'POST':
        action = request.POST.get('action', 'add')
        
        if action == 'delete':
            # Delete user
            user_id = request.POST.get('user_id')
            try:
                user = User.objects.get(id=user_id)
                if user.is_superuser:
                    message = 'Cannot delete superuser accounts.'
                    message_type = 'danger'
                else:
                    username = user.username
                    # Delete all KiteUser records for this user first
                    user.kite_users.all().delete()
                    user.delete()
                    message = f'User "{username}" deleted successfully.'
                    message_type = 'success'
            except User.DoesNotExist:
                message = 'User not found.'
                message_type = 'danger'
        
        elif action == 'edit':
            # Modify user password and role
            user_id = request.POST.get('user_id')
            form = EditAppUserForm(request.POST)
            if form.is_valid():
                try:
                    user = User.objects.get(id=user_id)
                    if user.is_superuser:
                        message = 'Cannot modify superuser accounts.'
                        message_type = 'danger'
                    else:
                        # Update password if provided
                        if form.cleaned_data['password']:
                            user.set_password(form.cleaned_data['password'])
                        # Update role
                        profile = user.profile
                        profile.role = form.cleaned_data['role']
                        profile.save()
                        user.save()
                        message = f'User "{user.username}" updated successfully.'
                        message_type = 'success'
                except User.DoesNotExist:
                    message = 'User not found.'
                    message_type = 'danger'
        
        else:
            # Add new user
            form = ManageZkUserForm(request.POST)
            if form.is_valid():
                new_user = User.objects.create_user(
                    username=form.cleaned_data['username'],
                    password=form.cleaned_data['password'],
                )
                # The ensure_profile signal already made a default self_only profile.
                profile = new_user.profile
                profile.role = form.cleaned_data['role']
                profile.save()
                message = f'User "{new_user.username}" created successfully.'
                message_type = 'success'
    
    # Prepare forms for display
    add_form = ManageZkUserForm()
    
    # All Kite accounts (admins see everyone) with live token status.
    rows = _user_rows(request.user)
    
    # Every app login user with their role (including those with no accounts).
    role_labels = dict(Profile.ROLE_CHOICES)
    app_users = []
    for u in User.objects.order_by('username'):
        profile = getattr(u, 'profile', None)
        role = getattr(profile, 'role', Profile.SELF_ONLY)
        if u.is_superuser:
            label, is_admin_user = 'Admin', True
        else:
            label = role_labels.get(role, 'Self only')
            is_admin_user = role == Profile.ADMIN_ONLY
        app_users.append({
            'user': u,
            'role_label': label,
            'is_admin': is_admin_user,
            'is_trader_all': role == Profile.TRADER_ALL,
            'role': role,
            'edit_form': EditAppUserForm(initial={'role': role}) if not u.is_superuser else None,
        })
    
    return render(request, 'app/managezkusers.html', {
        'title': 'Manage ZK Users',
        'year': datetime.now().year,
        'form': add_form,
        'rows': rows,
        'app_users': app_users,
        'message': message,
        'message_type': message_type,
    })


@login_required(login_url='login')
def token_statuses(request):
    """JSON: live token status per api_key, scoped to the requesting user.

    Polled by /configurezkauth, /trade and /deletezkuser to refresh the displayed
    access-token status from the live Zerodha API every 10 minutes.
    """
    owner_filter = request.GET.get('owner', '') if can_trade_all(request.user) else ''
    statuses = {}
    statuses_by_id = {}
    for row in _user_rows(request.user, owner_filter):
        payload = {
            'status': row['status'],
            'label': row['presentation']['label'],
            'css': row['presentation']['css'],
            'checked_at': row['checked_at'].isoformat(),
            'checked_at_display': row['checked_at'].strftime('%Y-%m-%d %H:%M:%S'),
        }
        statuses[row['user'].api_key] = payload
        statuses_by_id[row['user'].zk_user_id] = payload
    return JsonResponse({'statuses': statuses, 'statuses_by_id': statuses_by_id})


def _owner_choices():
    """App login users owning at least one Kite account (admin owner dropdowns)."""
    return User.objects.filter(kite_users__isnull=False).distinct().order_by('username')


@account_config_required
def configurezkauth(request):
    """Lists configured Zerodha users; adds and authenticates via manual or automated flow."""
    assert isinstance(request, HttpRequest)
    owner_filter = request.GET.get('owner', '') if is_admin(request.user) else ''
    context = {
        'title': 'Configure ZK Auth',
        'year': datetime.now().year,
        'is_admin': is_admin(request.user),
        'owners': _owner_choices() if is_admin(request.user) else [],
        'owner_filter': owner_filter,
        'rows': _user_rows(request.user, owner_filter),
        'redirect_url': request.build_absolute_uri(reverse('kite_callback')),
    }

    reauth_id = request.GET.get('reauth')
    if reauth_id:
        user = get_object_or_404(KiteUser, zk_user_id=reauth_id)
        if not is_admin(request.user) and user.owner_id != request.user.id:
            return redirect('configurezkauth')
        if not user.api_secret:
            return redirect('configurezkauth')
        try:
            next_url = _start_reauthentication(request, user)
            if next_url:
                return redirect(next_url)
            context['success'] = True
            context['result'] = True
            context['message'] = 'Authentication succeeded for {0}.'.format(user.user_name or user.user_id or user.zk_user_id)
        except Exception as ex:
            context['success'] = False
            context['result'] = True
            context['message'] = 'Authentication failed: {0}'.format(ex)
        context['form'] = AddUserForm()
        context['rows'] = _user_rows(request.user, owner_filter)
        return render(request, 'app/adduser.html', context)

    if request.method == 'POST':
        if request.POST.get('action') == 'edit_credentials':
            edit_form = EditKiteCredentialsForm(request.POST)
            if edit_form.is_valid():
                zk_user_id = edit_form.cleaned_data['zk_user_id']
                user = get_object_or_404(KiteUser, zk_user_id=zk_user_id)
                if not is_admin(request.user) and user.owner_id != request.user.id:
                    return redirect('configurezkauth')

                new_api_key = (edit_form.cleaned_data.get('api_key') or '').strip()
                new_api_secret = (edit_form.cleaned_data.get('api_secret') or '').strip()
                new_password = (edit_form.cleaned_data.get('zerodha_password') or '').strip()
                new_totp = (edit_form.cleaned_data.get('zerodha_totp_key') or '').strip()

                if new_api_key and new_api_key != user.api_key:
                    exists = KiteUser.objects.exclude(pk=user.pk).filter(api_key=new_api_key).exists()
                    if exists:
                        context['page_message'] = 'API key is already in use by another Zerodha user.'
                        context['page_message_type'] = 'danger'
                        context['form'] = AddUserForm()
                        context['rows'] = _user_rows(request.user, owner_filter)
                        return render(request, 'app/adduser.html', context)
                    user.api_key = new_api_key

                if new_api_secret:
                    user.api_secret = new_api_secret
                if new_password:
                    user.zerodha_password = new_password
                if new_totp:
                    user.zerodha_totp_key = new_totp

                user.save()
                context['page_message'] = 'Zerodha credentials updated successfully for {0}.'.format(user.zk_user_id)
                context['page_message_type'] = 'success'
            else:
                context['page_message'] = 'Invalid edit request. Please review the entered fields.'
                context['page_message_type'] = 'danger'

            context['form'] = AddUserForm()
            context['rows'] = _user_rows(request.user, owner_filter)
            return render(request, 'app/adduser.html', context)

        form = AddUserForm(request.POST)
        if form.is_valid():
            cleaned = form.cleaned_data
            existing = KiteUser.objects.filter(api_key=cleaned['api_key']).first()
            if existing and existing.owner_id != request.user.id and not is_admin(request.user):
                context['success'] = False
                context['result'] = True
                context['message'] = 'This API key is already configured for another app user.'
                context['form'] = form
                return render(request, 'app/adduser.html', context)
            user, _created = KiteUser.objects.update_or_create(
                api_key=cleaned['api_key'],
                defaults={
                    'api_secret': cleaned['api_secret'],
                    'manual_token': False,
                    'automate': cleaned['automate'],
                    'zerodha_password': cleaned.get('zerodha_password', ''),
                    'zerodha_totp_key': cleaned.get('zerodha_totp_key', ''),
                    # Zerodha username field must be populated and overwritten from /user/profile when available.
                    'user_name': cleaned['zerodha_username'],
                    # User ID starts from form username so automated login can run before first profile sync.
                    'user_id': cleaned['zerodha_username'],
                    'owner': request.user,
                }
            )
            try:
                next_url = _start_reauthentication(request, user)
                if next_url:
                    return redirect(next_url)
                context['success'] = True
                context['result'] = True
                context['message'] = 'User added and authentication completed for {0}.'.format(user.user_name or user.user_id or user.zk_user_id)
            except Exception as ex:
                context['success'] = False
                context['result'] = True
                context['message'] = 'User added, but authentication failed: {0}'.format(ex)
            context['form'] = AddUserForm()
            context['rows'] = _user_rows(request.user, owner_filter)
            return render(request, 'app/adduser.html', context)
    else:
        form = AddUserForm()
    context['form'] = form
    return render(request, 'app/adduser.html', context)


@login_required(login_url='login')
def kite_callback(request):
    """Handles the Kite redirect, exchanges request_token for an access_token."""
    assert isinstance(request, HttpRequest)
    request_token = request.GET.get('request_token')
    status = request.GET.get('status')
    pending_id = request.session.pop('pending_zk_user_id', None)
    api_key = request.GET.get('api_key')

    success, message = False, 'Authentication failed.'
    if status and status != 'success':
        message = 'Kite login was not successful: {0}'.format(status)
    elif not request_token:
        message = 'Missing request_token in redirect.'
    elif not pending_id and not api_key:
        message = 'No pending user to authenticate. Start from Configure ZK Auth.'
    else:
        try:
            if pending_id:
                user = KiteUser.objects.get(zk_user_id=pending_id)
            else:
                user = KiteUser.objects.get(api_key=api_key)
            if user.owner_id != request.user.id and not is_admin(request.user):
                return redirect('configurezkauth')
            kite = _make_kite(user.api_key)
            data = kite.generate_session(request_token, api_secret=user.api_secret)
            _persist_token_data(user, data)
            _sync_profile_from_kite(user)
            success = True
            message = 'Authentication succeeded for {0}.'.format(user.user_name or user.user_id or user.zk_user_id)
        except KiteUser.DoesNotExist:
            message = 'No stored user for that API key.'
        except KiteException as ex:
            message = 'Authentication failed: {0}'.format(ex)

    return render(
        request,
        'app/adduser.html',
        {
            'title': 'Configure ZK Auth',
            'year': datetime.now().year,
            'form': AddUserForm(),
            'result': True,
            'success': success,
            'message': message,
        }
    )


def _scalar_value(value):
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            return int(value) if value.isdigit() else float(value)
        except ValueError:
            return value
    if isinstance(value, dict):
        for subkey in ('value', 'amount', 'used', 'utilised', 'utilized', 'margin_used', 'net', 'live_balance', 'available'):
            if subkey in value and value[subkey] is not None:
                return _scalar_value(value[subkey])
    if isinstance(value, list) and value:
        return _scalar_value(value[0])
    return None


def _sum_numeric_values(value):
    """Recursively sums numeric values from nested dict/list payloads."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    if isinstance(value, dict):
        total = 0.0
        found = False
        for item in value.values():
            amount = _sum_numeric_values(item)
            if amount is not None:
                total += amount
                found = True
        return total if found else None
    if isinstance(value, list):
        total = 0.0
        found = False
        for item in value:
            amount = _sum_numeric_values(item)
            if amount is not None:
                total += amount
                found = True
        return total if found else None
    return None


def _calculate_margin_used(margins):
    if not isinstance(margins, dict):
        return None

    segments = []
    for segment_name in ('equity', 'commodity'):
        segment = margins.get(segment_name)
        if isinstance(segment, dict):
            segments.append(segment)
    if not segments:
        segments = [margins]

    total_used = 0.0
    found = False
    for segment in segments:
        segment_used = None
        for key in ('utilised', 'utilized', 'used', 'margin_used'):
            if key in segment and segment[key] is not None:
                segment_used = _sum_numeric_values(segment[key])
                break
        if segment_used is not None:
            total_used += segment_used
            found = True

    return round(total_used, 2) if found else None


def _normalize_position(position):
    if not isinstance(position, dict):
        return position
    quantity = position.get('quantity')
    if quantity is None:
        quantity = position.get('net_quantity') or position.get('day_buy_quantity') or position.get('day_sell_quantity') or position.get('sell_quantity') or position.get('buy_quantity')
    average_price = position.get('average_price') or position.get('avg_price') or position.get('price') or position.get('last_price')
    normalized = dict(position)
    normalized['quantity'] = _scalar_value(quantity)
    normalized['average_price'] = _scalar_value(average_price)
    return normalized


def _get_trade_user(api_key, request_user):
    qs = KiteUser.objects.exclude(access_token='')
    if not can_trade_all(request_user):
        qs = qs.filter(owner=request_user)
    return qs.filter(api_key=api_key).first()


def _trade_data_for_user(user):
    def _fetch(kite):
        profile = kite.profile()
        orders = kite.orders()
        margins = kite.margins()
        holdings = kite.holdings()
        positions = kite.positions()
        return profile, orders, margins, holdings, positions

    profile, orders, margins, holdings, positions = _call_with_token_renewal(user, _fetch)
    if isinstance(positions, dict):
        positions = positions.get('net', [])
    positions = [_normalize_position(p) for p in positions]
    segment = margins.get('equity', {}) if isinstance(margins, dict) and isinstance(margins.get('equity'), dict) else margins
    available = segment.get('available', {}) if isinstance(segment, dict) and isinstance(segment.get('available'), dict) else {}
    utilised = segment.get('utilised', {}) if isinstance(segment, dict) and isinstance(segment.get('utilised'), dict) else {}
    return {
        'profile': profile,
        'open_orders': [o for o in orders if o.get('status') == 'OPEN'],
        'executed_orders': [o for o in orders if o.get('status') == 'COMPLETE'],
        'cancelled_orders': [o for o in orders if o.get('status') == 'CANCELLED'],
        'holdings': holdings,
        'positions': positions,
        'holdings_pnl': sum(_scalar_value(h.get('pnl', 0)) or 0 for h in holdings),
        'positions_pnl': sum(_scalar_value(p.get('pnl', 0)) or 0 for p in positions),
        'net': _scalar_value(segment.get('net')) if isinstance(segment, dict) else None,
        'opening_balance': _scalar_value(available.get('opening_balance')),
        'live_balance': _scalar_value(available.get('live_balance')),
        'cash': _scalar_value(available.get('cash')),
        'debits': _scalar_value(utilised.get('debits')),
    }


def _empty_trade_data():
    return {
        'profile': None,
        'open_orders': [],
        'executed_orders': [],
        'cancelled_orders': [],
        'holdings': [],
        'positions': [],
        'holdings_pnl': 0,
        'positions_pnl': 0,
        'net': None,
        'opening_balance': None,
        'live_balance': None,
        'cash': None,
        'debits': None,
    }


@login_required(login_url='login')
def trade(request):
    """Shows trading data for a selected authenticated user."""
    assert isinstance(request, HttpRequest)
    trade_all = can_trade_all(request.user)
    users = KiteUser.objects.exclude(access_token='').select_related('owner').order_by('user_name')
    if not trade_all:
        users = users.filter(owner=request.user)
    selected = request.GET.get('api_key', '')
    context = {
        'title': 'Trade',
        'year': datetime.now().year,
        'users': users,
        'selected': selected,
        'trade_all': trade_all,
        'banner': request.GET.get('msg', ''),
        'banner_level': 'success' if request.GET.get('level') == 'success' else 'danger',
    }
    if selected:
        user = get_object_or_404(KiteUser, api_key=selected)
        if not trade_all and user.owner_id != request.user.id:
            context['error'] = 'Not authorized for this account.'
            return render(request, 'app/trade.html', context)
        context['selected_status'] = _status_presentation(_auth_status(user))
        try:
            context.update(_trade_data_for_user(user))
        except KiteException:
            context.update(_empty_trade_data())
    return render(request, 'app/trade.html', context)


@login_required(login_url='login')
def trade_refresh_data(request):
    api_key = request.GET.get('api_key', '')
    selected_api_key = request.GET.get('selected_api_key', '')
    if api_key == 'all':
        if not can_trade_all(request.user):
            return JsonResponse({'error': 'Not authorized to refresh all accounts.'}, status=403)
        users = KiteUser.objects.exclude(access_token='').select_related('owner').order_by('user_name')
        for user in users:
            try:
                _trade_data_for_user(user)
            except KiteException:
                pass
        if not selected_api_key:
            return JsonResponse({'error': 'Missing selected_api_key for current trade view.'}, status=400)
        kite_user = _get_trade_user(selected_api_key, request.user)
        if not kite_user:
            return JsonResponse({'error': 'Selected user not authorized or not found.'}, status=403)
    else:
        if not api_key:
            return JsonResponse({'error': 'Missing api_key.'}, status=400)
        kite_user = _get_trade_user(api_key, request.user)
        if not kite_user:
            return JsonResponse({'error': 'Not authorized or user not found.'}, status=403)
    try:
        data = _trade_data_for_user(kite_user)
    except KiteException:
        data = _empty_trade_data()
    data['selected_status'] = _status_presentation(_auth_status(kite_user))
    data['api_key'] = kite_user.api_key
    return JsonResponse(data)


@account_config_required
def deletezkuser(request):
    """Lists stored users and deletes the selected one (this app's DB only).
    
    Only admin users can delete any user; self_only users can only delete their own.
    """
    assert isinstance(request, HttpRequest)
    admin = is_admin(request.user)
    if request.method == 'POST':
        qs = KiteUser.objects.all()
        if not admin:
            qs = qs.filter(owner=request.user)
        qs.filter(api_key=request.POST.get('api_key', '')).delete()
        return redirect('deletezkuser')
    owner_filter = request.GET.get('owner', '') if admin else ''
    return render(
        request,
        'app/deleteuser.html',
        {
            'title': 'Delete ZK User',
            'year': datetime.now().year,
            'rows': _user_rows(request.user, owner_filter),
            'is_admin': admin,
            'owners': _owner_choices() if admin else [],
            'owner_filter': owner_filter,
        }
    )


def _user_kite(api_key, request_user=None):
    """Returns a token-set Kite client for the stored user, or None.

    When request_user is given, enforces ownership unless they can trade all.
    """
    qs = KiteUser.objects.filter(api_key=api_key).exclude(access_token='')
    if request_user is not None and not can_trade_all(request_user):
        qs = qs.filter(owner=request_user)
    user = qs.first()
    if not user:
        return None
    try:
        _call_with_token_renewal(user, lambda kite: kite.profile())
    except TokenException:
        return None
    except KiteException:
        # Non-token errors (for example, transient network issues) should not
        # block the caller; the endpoint will handle the downstream error.
        pass
    return _make_kite(user.api_key, user.access_token)


def _trade_redirect(api_key, level, message):
    """Redirects to /trade preserving the user and a status banner."""
    qs = urlencode({'api_key': api_key, 'level': level, 'msg': message})
    return redirect('{0}?{1}'.format(reverse('trade'), qs))


def _get_instruments(kite, exchange):
    """Returns cached instruments for an exchange (refreshed hourly)."""
    cached = _INSTRUMENTS_CACHE.get(exchange)
    if cached and (time.time() - cached[0]) < _INSTRUMENTS_TTL:
        return cached[1]
    data = kite.instruments(exchange)
    _INSTRUMENTS_CACHE[exchange] = (time.time(), data)
    return data


@login_required(login_url='login')
def instruments_search(request):
    """JSON: best-match tradingsymbols for a query on an exchange."""
    kite = _user_kite(request.GET.get('api_key', ''), request.user)
    if not kite:
        return JsonResponse({'results': []})
    query = request.GET.get('q', '').upper()
    exchange = request.GET.get('exchange', 'NSE')
    results = []
    if query:
        for inst in _get_instruments(kite, exchange):
            sym = inst.get('tradingsymbol', '')
            if query in sym:
                results.append({'symbol': sym, 'name': inst.get('name', '')})
                if len(results) >= 20:
                    break
    return JsonResponse({'results': results})


@login_required(login_url='login')
def instruments_all(request):
    """JSON: full NSE+BSE symbol list for client-side autocomplete (cached)."""
    kite = _user_kite(request.GET.get('api_key', ''), request.user)
    if not kite:
        return JsonResponse({'results': []})
    out = []
    for exch in ('NSE', 'BSE'):
        for inst in _get_instruments(kite, exch):
            out.append({'symbol': inst.get('tradingsymbol', ''),
                        'name': inst.get('name', ''),
                        'exchange': exch})
    return JsonResponse({'results': out})


@login_required(login_url='login')
def quote(request):
    """JSON: last price and upper/lower circuit for an exchange:symbol."""
    kite = _user_kite(request.GET.get('api_key', ''), request.user)
    symbol = request.GET.get('symbol', '')
    exchange = request.GET.get('exchange', 'NSE')
    if not kite or not symbol:
        return JsonResponse({'ok': False})
    key = '{0}:{1}'.format(exchange, symbol)
    try:
        data = kite.quote(key).get(key, {})
    except KiteException as ex:
        return JsonResponse({'ok': False, 'error': str(ex)})
    circuit = data.get('circuit_limit', {}) or {}
    return JsonResponse({
        'ok': True,
        'last_price': data.get('last_price'),
        'lower': circuit.get('lower'),
        'upper': circuit.get('upper'),
    })


def _validate_circuit(kite, exchange, symbol, order_type, price):
    """For LIMIT orders, ensure price is within the day's circuit band."""
    if order_type != KiteConnect.ORDER_TYPE_LIMIT:
        return None
    key = '{0}:{1}'.format(exchange, symbol)
    try:
        band = kite.quote(key).get(key, {}).get('circuit_limit', {}) or {}
    except KiteException:
        return None
    lower, upper = band.get('lower'), band.get('upper')
    if lower is not None and upper is not None and not (lower <= price <= upper):
        return 'Price {0} is outside circuit band {1}-{2}.'.format(price, lower, upper)
    return None


def _place(kite, p):
    """Places a regular order from a dict of POST params; returns order_id."""
    order_type = p.get('order_type', 'MARKET')
    price = float(p['price']) if p.get('price') else None
    err = _validate_circuit(kite, p['exchange'], p['tradingsymbol'], order_type, price)
    if err:
        raise ValueError(err)
    return kite.place_order(
        variety=KiteConnect.VARIETY_REGULAR,
        exchange=p['exchange'],
        tradingsymbol=p['tradingsymbol'],
        transaction_type=p['transaction_type'],
        quantity=int(p['quantity']),
        product=p.get('product', 'CNC'),
        order_type=order_type,
        price=price,
        validity=KiteConnect.VALIDITY_DAY,
    )


@require_POST
@login_required(login_url='login')
def trade_place(request):
    """Places a new order for the selected user."""
    api_key = request.POST.get('api_key', '')
    kite = _user_kite(api_key, request.user)
    if not kite:
        return _trade_redirect(api_key, 'error', 'No authenticated user selected.')
    try:
        order_id = _place(kite, request.POST)
        return _trade_redirect(api_key, 'success', 'Order placed (ID {0}).'.format(order_id))
    except (KiteException, ValueError, KeyError) as ex:
        return _trade_redirect(api_key, 'error', 'Place failed: {0}'.format(ex))


@require_POST
@login_required(login_url='login')
def trade_cancel(request):
    """Cancels an open order."""
    api_key = request.POST.get('api_key', '')
    kite = _user_kite(api_key, request.user)
    if not kite:
        return _trade_redirect(api_key, 'error', 'No authenticated user selected.')
    try:
        kite.cancel_order(variety=KiteConnect.VARIETY_REGULAR,
                          order_id=request.POST.get('order_id'))
        return _trade_redirect(api_key, 'success', 'Order cancelled.')
    except KiteException as ex:
        return _trade_redirect(api_key, 'error', 'Cancel failed: {0}'.format(ex))


@require_POST
@login_required(login_url='login')
def trade_modify(request):
    """Modifies an open order; exchange change = cancel and re-place."""
    p = request.POST
    api_key = p.get('api_key', '')
    kite = _user_kite(api_key, request.user)
    if not kite:
        return _trade_redirect(api_key, 'error', 'No authenticated user selected.')
    try:
        if p.get('new_exchange') and p.get('new_exchange') != p.get('exchange'):
            kite.cancel_order(variety=KiteConnect.VARIETY_REGULAR, order_id=p.get('order_id'))
            _place(kite, {**p.dict(), 'exchange': p.get('new_exchange')})
            return _trade_redirect(api_key, 'success', 'Order cancelled and re-placed on new exchange.')
        kite.modify_order(
            variety=KiteConnect.VARIETY_REGULAR,
            order_id=p.get('order_id'),
            quantity=int(p['quantity']),
            price=float(p['price']) if p.get('price') else None,
            order_type=p.get('order_type'),
        )
        return _trade_redirect(api_key, 'success', 'Order modified.')
    except (KiteException, ValueError, KeyError) as ex:
        return _trade_redirect(api_key, 'error', 'Modify failed: {0}'.format(ex))

