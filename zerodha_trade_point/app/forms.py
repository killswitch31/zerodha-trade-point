"""
Definition of forms.
"""

import hashlib
import requests
from django import forms
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _
from app.models import Profile

class BootstrapAuthenticationForm(AuthenticationForm):
    """Authentication form which uses boostrap CSS."""
    username = forms.CharField(max_length=254,
                               widget=forms.TextInput({
                                   'class': 'form-control',
                                   'placeholder': 'User name'}))
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput({
                                   'class': 'form-control',
                                   'placeholder':'Password'}))
    captcha_token = forms.CharField(required=False, widget=forms.HiddenInput())

    def __init__(self, request=None, *args, **kwargs):
        super().__init__(request=request, *args, **kwargs)
        self.captcha_enabled = bool(settings.TURNSTILE_SITE_KEY and settings.TURNSTILE_SECRET_KEY)
        self.captcha_site_key = settings.TURNSTILE_SITE_KEY

    def _client_ip(self):
        if not self.request:
            return 'unknown'
        forwarded_for = (self.request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
        return forwarded_for or self.request.META.get('REMOTE_ADDR', 'unknown')

    def _rate_limit_key(self, username):
        principal = '{0}|{1}'.format(self._client_ip(), (username or '').strip().lower())
        digest = hashlib.sha256(principal.encode('utf-8')).hexdigest()
        return 'login-rate-limit:{0}'.format(digest)

    def _rate_limit_message(self):
        window_seconds = max(settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS, 1)
        window_minutes = max(1, window_seconds // 60)
        return 'Too many login attempts. Try again in {0} minute(s).'.format(window_minutes)

    def _check_rate_limit(self, username):
        if settings.LOGIN_RATE_LIMIT_ATTEMPTS <= 0:
            return None
        failures = cache.get(self._rate_limit_key(username), 0)
        if failures >= settings.LOGIN_RATE_LIMIT_ATTEMPTS:
            raise forms.ValidationError(self._rate_limit_message())
        return failures

    def _record_failed_attempt(self, username, existing_failures):
        if settings.LOGIN_RATE_LIMIT_ATTEMPTS <= 0:
            return
        cache.set(
            self._rate_limit_key(username),
            int(existing_failures or 0) + 1,
            timeout=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        )

    def _clear_failed_attempts(self, username):
        if settings.LOGIN_RATE_LIMIT_ATTEMPTS <= 0:
            return
        cache.delete(self._rate_limit_key(username))

    def _validate_captcha(self, cleaned):
        if not self.captcha_enabled:
            return

        token = (cleaned.get('captcha_token') or '').strip()
        if not token:
            raise forms.ValidationError('Complete the CAPTCHA challenge before logging in.')

        payload = {
            'secret': settings.TURNSTILE_SECRET_KEY,
            'response': token,
        }
        remote_ip = self._client_ip()
        if remote_ip and remote_ip != 'unknown':
            payload['remoteip'] = remote_ip

        try:
            response = requests.post(
                'https://challenges.cloudflare.com/turnstile/v0/siteverify',
                data=payload,
                timeout=10,
            )
            response.raise_for_status()
            result = response.json()
        except requests.RequestException as ex:
            raise forms.ValidationError('CAPTCHA verification is temporarily unavailable. Try again.') from ex

        if not result.get('success'):
            raise forms.ValidationError('CAPTCHA verification failed. Try again.')

    def clean(self):
        username = self.data.get('username', '')
        failures = self._check_rate_limit(username)

        try:
            cleaned = self.cleaned_data
            self._validate_captcha(cleaned)
            cleaned = super().clean()
        except forms.ValidationError:
            self._record_failed_attempt(username, failures)
            raise

        self._clear_failed_attempts(username)
        return cleaned


class AddUserForm(forms.Form):
    """Collects Zerodha credentials for standard OAuth authentication."""
    zerodha_username = forms.CharField(max_length=64,
                                       widget=forms.TextInput({
                                           'class': 'form-control',
                                           'placeholder': 'Zerodha username'}))
    api_key = forms.CharField(max_length=64,
                              widget=forms.TextInput({
                                  'class': 'form-control',
                                  'placeholder': 'API key'}))
    api_secret = forms.CharField(max_length=128,
                                 widget=forms.PasswordInput({
                                     'class': 'form-control',
                                     'placeholder': 'API secret'}))

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get('zerodha_username'):
            self.add_error('zerodha_username', 'Zerodha username is required.')
        if not cleaned.get('api_key'):
            self.add_error('api_key', 'API key is required.')
        if not cleaned.get('api_secret'):
            self.add_error('api_secret', 'API secret is required.')
        return cleaned


class ManageZkUserForm(forms.Form):
    """Admin-only: provision a new Django login user with a role."""
    username = forms.CharField(max_length=150,
                               widget=forms.TextInput({
                                   'class': 'form-control',
                                   'placeholder': 'User name'}))
    password = forms.CharField(
        widget=forms.PasswordInput({
            'class': 'form-control',
            'placeholder': 'Password'}))
    role = forms.ChoiceField(choices=Profile.ROLE_CHOICES,
                             initial=Profile.SELF_ONLY,
                             widget=forms.Select({'class': 'form-control'}))

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError('That username is already taken.')
        return username


class EditAppUserForm(forms.Form):
    """Admin-only: modify password and role for an existing app user."""
    password = forms.CharField(required=False,
                               widget=forms.PasswordInput({
                                   'class': 'form-control',
                                   'placeholder': 'Leave blank to keep current password'}))
    role = forms.ChoiceField(choices=Profile.ROLE_CHOICES,
                             widget=forms.Select({'class': 'form-control'}))


class EditKiteCredentialsForm(forms.Form):
    """Edits API credentials for an existing configured Zerodha user."""
    zk_user_id = forms.CharField(max_length=24)
    api_key = forms.CharField(required=False, max_length=64,
                              widget=forms.TextInput({'class': 'form-control'}))
    api_secret = forms.CharField(required=False, max_length=128,
                                 widget=forms.PasswordInput({'class': 'form-control'}))
    clear_api_key = forms.BooleanField(required=False)
    clear_api_secret = forms.BooleanField(required=False)

