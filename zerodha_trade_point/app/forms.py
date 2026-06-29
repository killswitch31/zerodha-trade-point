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
    """Collects credentials: API key+secret (oauth) or a direct bearer token."""
    METHOD_CHOICES = (('oauth', 'API key + secret'), ('bearer', 'Bearer token'))
    method = forms.ChoiceField(choices=METHOD_CHOICES, initial='oauth',
                               widget=forms.RadioSelect)
    api_key = forms.CharField(max_length=64,
                              widget=forms.TextInput({
                                  'class': 'form-control',
                                  'placeholder': 'API key'}))
    api_secret = forms.CharField(max_length=128, required=False,
                                 widget=forms.PasswordInput({
                                     'class': 'form-control',
                                     'placeholder': 'API secret'}))
    access_token = forms.CharField(max_length=128, required=False,
                                   widget=forms.TextInput({
                                       'class': 'form-control',
                                       'placeholder': 'Bearer / access token'}))

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('method') == 'bearer':
            if not cleaned.get('access_token'):
                self.add_error('access_token', 'Access token is required.')
        elif not cleaned.get('api_secret'):
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

