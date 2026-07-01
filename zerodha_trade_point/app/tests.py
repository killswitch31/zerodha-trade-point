"""Tests for configure auth form rules and token status JSON behavior."""

import json
from unittest.mock import patch
from django.contrib.auth.models import User
from django.test import TestCase, RequestFactory, override_settings
from django.urls import reverse
from app.forms import AddUserForm
from app.models import KiteUser
from app.views import token_statuses, configurezkauth


class AddUserFormTests(TestCase):
    def _base_payload(self):
        return {
            'zerodha_username': 'AB1234',
            'api_key': 'key-123',
            'api_secret': 'secret-123',
            'automate': '0',
            'zerodha_password': '',
            'zerodha_totp_key': '',
        }

    def test_automate_no_does_not_require_password_or_totp(self):
        form = AddUserForm(data=self._base_payload())
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['automate'], 0)

    def test_automate_yes_requires_password_and_totp(self):
        payload = self._base_payload()
        payload['automate'] = '1'
        form = AddUserForm(data=payload)
        self.assertFalse(form.is_valid())
        self.assertIn('zerodha_password', form.errors)
        self.assertIn('zerodha_totp_key', form.errors)

    def test_automate_yes_valid_when_password_and_totp_given(self):
        payload = self._base_payload()
        payload.update({
            'automate': '1',
            'zerodha_password': 'pass-123',
            'zerodha_totp_key': 'BASE32KEY',
        })
        form = AddUserForm(data=payload)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['automate'], 1)


class TokenStatusesTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='alice', password='alice-pass')
        self.other = User.objects.create_user(username='bob', password='bob-pass')
        self.user_account = KiteUser.objects.create(
            owner=self.user,
            api_key='api-alice',
            api_secret='sec-alice',
            access_token='tok-alice',
            user_name='Alice Kite',
            user_id='AB1234',
        )
        self.other_account = KiteUser.objects.create(
            owner=self.other,
            api_key='api-bob',
            api_secret='sec-bob',
            access_token='tok-bob',
            user_name='Bob Kite',
            user_id='CD5678',
        )

    @patch('app.views._auth_status', return_value='active')
    def test_token_statuses_only_returns_logged_in_user_accounts(self, _mock_status):
        request = self.factory.get(reverse('token_statuses'))
        request.user = self.user
        response = token_statuses(request)
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)

        self.assertIn('statuses', payload)
        self.assertIn('statuses_by_id', payload)
        self.assertIn(self.user_account.api_key, payload['statuses'])
        self.assertNotIn(self.other_account.api_key, payload['statuses'])
        self.assertIn(self.user_account.zk_user_id, payload['statuses_by_id'])
        self.assertNotIn(self.other_account.zk_user_id, payload['statuses_by_id'])

    @patch('app.views._auth_status', return_value='active')
    def test_token_status_payload_includes_last_checked_timestamp(self, _mock_status):
        request = self.factory.get(reverse('token_statuses'))
        request.user = self.user
        response = token_statuses(request)
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)['statuses'][self.user_account.api_key]

        self.assertEqual(payload['label'], 'Active')
        self.assertEqual(payload['css'], 'label-success')
        self.assertIn('checked_at', payload)
        self.assertIn('checked_at_display', payload)


class ConfigureZkAuthEditCredentialsTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='owner', password='owner-pass')
        self.other = User.objects.create_user(username='other', password='other-pass')
        self.kite_user = KiteUser.objects.create(
            owner=self.user,
            api_key='owner-api',
            api_secret='owner-secret',
            access_token='owner-token',
            user_name='Owner Kite',
            user_id='OW1234',
            zerodha_password='old-password',
            zerodha_totp_key='OLDTOTP',
            automate=1,
        )
        self.other_kite_user = KiteUser.objects.create(
            owner=self.other,
            api_key='other-api',
            api_secret='other-secret',
            access_token='other-token',
            user_name='Other Kite',
            user_id='OT5678',
        )

    def _post_edit(self, user, payload):
        request = self.factory.post(reverse('configurezkauth'), payload)
        request.user = user
        request.session = {}
        return configurezkauth(request)

    @patch('app.views._auth_status', return_value='active')
    def test_owner_can_edit_one_or_many_fields(self, _mock_status):
        response = self._post_edit(self.user, {
            'action': 'edit_credentials',
            'zk_user_id': self.kite_user.zk_user_id,
            'api_key': 'owner-api-new',
            'api_secret': 'owner-secret-new',
            'zerodha_password': '',
            'zerodha_totp_key': 'NEWTOTP',
            'automate': '0',
        })
        self.assertEqual(response.status_code, 200)
        self.kite_user.refresh_from_db()
        self.assertEqual(self.kite_user.api_key, 'owner-api-new')
        self.assertEqual(self.kite_user.api_secret, 'owner-secret-new')
        self.assertEqual(self.kite_user.zerodha_totp_key, 'NEWTOTP')
        self.assertEqual(self.kite_user.automate, 0)
        # Blank field should preserve existing secret value.
        self.assertEqual(self.kite_user.zerodha_password, 'old-password')

    @patch('app.views._auth_status', return_value='active')
    def test_non_owner_cannot_edit_another_users_credentials(self, _mock_status):
        response = self._post_edit(self.other, {
            'action': 'edit_credentials',
            'zk_user_id': self.kite_user.zk_user_id,
            'api_key': 'hijack-api',
            'api_secret': 'hijack-secret',
            'zerodha_password': 'hijack-pass',
            'zerodha_totp_key': 'HIJACKTOTP',
            'automate': '0',
        })
        self.assertEqual(response.status_code, 302)
        self.kite_user.refresh_from_db()
        self.assertEqual(self.kite_user.api_key, 'owner-api')
        self.assertEqual(self.kite_user.api_secret, 'owner-secret')
        self.assertEqual(self.kite_user.zerodha_password, 'old-password')
        self.assertEqual(self.kite_user.zerodha_totp_key, 'OLDTOTP')

    @patch('app.views._auth_status', return_value='active')
    def test_api_key_collision_is_rejected(self, _mock_status):
        response = self._post_edit(self.user, {
            'action': 'edit_credentials',
            'zk_user_id': self.kite_user.zk_user_id,
            'api_key': self.other_kite_user.api_key,
            'api_secret': '',
            'zerodha_password': '',
            'zerodha_totp_key': '',
            'automate': '1',
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'API key is already in use by another Zerodha user.', response.content)
        self.kite_user.refresh_from_db()
        self.assertEqual(self.kite_user.api_key, 'owner-api')

    @patch('app.views._auth_status', return_value='active')
    def test_invalid_automate_value_is_rejected(self, _mock_status):
        response = self._post_edit(self.user, {
            'action': 'edit_credentials',
            'zk_user_id': self.kite_user.zk_user_id,
            'api_key': 'owner-api',
            'api_secret': '',
            'zerodha_password': '',
            'zerodha_totp_key': '',
            'automate': '3',
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid edit request. Please review the entered fields.', response.content)
        self.kite_user.refresh_from_db()
        self.assertEqual(self.kite_user.automate, 1)
