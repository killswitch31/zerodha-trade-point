"""
Definition of forms.
"""

from django import forms
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

