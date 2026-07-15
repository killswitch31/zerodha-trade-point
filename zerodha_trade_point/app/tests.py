"""Tests for Configure ZK Auth behavior and token status payloads."""

import json
from unittest.mock import patch
from django.contrib import admin
from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase, RequestFactory, override_settings
from django.urls import reverse
from requests import RequestException
from kiteconnect.exceptions import KiteException
from kiteconnect.exceptions import TokenException
from app.admin import UserWithRoleAdmin
from app.forms import AddUserForm, BootstrapAuthenticationForm, ManageZkUserForm
from app.models import KiteUser, Profile, generate_kite_user_identifier
from app.context_processors import user_role
from app.middleware import LoginRequiredMiddleware
from app.views import token_statuses, configurezkauth, _kite_login_url, _kite_callback_url, trade, _place, trade_modify, _trade_data_for_user, is_admin, can_trade_all, can_configure_accounts, _persist_token_data, _renew_access_token, _call_with_token_renewal, _auth_status, managezkusers, kite_callback, _scalar_value, _sum_numeric_values, _calculate_margin_used, _normalize_position, trade_refresh_data, deletezkuser, _user_kite, instruments_search, instruments_all, quote, _INSTRUMENTS_CACHE, trade_place, trade_cancel, _validate_circuit, _user_rows, _sync_profile_from_kite, _owner_choices, _make_kite, _get_instruments, _get_trade_user, trade_convert_position, _normalize_product, _empty_trade_data


class AddUserFormTests(TestCase):
    def _payload(self):
        return {
            'zerodha_username': 'AB1234',
            'api_key': 'key-123',
            'api_secret': 'secret-123',
        }

    def test_required_fields_present(self):
        form = AddUserForm(data=self._payload())
        self.assertTrue(form.is_valid())

    def test_api_key_required(self):
        payload = self._payload()
        payload['api_key'] = ''
        form = AddUserForm(data=payload)
        self.assertFalse(form.is_valid())
        self.assertIn('api_key', form.errors)

    def test_api_secret_required(self):
        payload = self._payload()
        payload['api_secret'] = ''
        form = AddUserForm(data=payload)
        self.assertFalse(form.is_valid())
        self.assertIn('api_secret', form.errors)

    def test_zerodha_username_required(self):
        payload = self._payload()
        payload['zerodha_username'] = ''
        form = AddUserForm(data=payload)
        self.assertFalse(form.is_valid())
        self.assertIn('zerodha_username', form.errors)


class ManageZkUserFormValidationTests(TestCase):
    def test_duplicate_username_rejected_case_insensitively(self):
        User.objects.create_user(username='Alice', password='alice-pass')

        form = ManageZkUserForm(data={
            'username': 'alice',
            'password': 'new-pass',
            'role': Profile.SELF_ONLY,
        })

        self.assertFalse(form.is_valid())
        self.assertIn('That username is already taken.', form.errors['username'])


class LoginProtectionFormTests(TestCase):
    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='login-user', password='safe-pass-123')

    def _request(self, data=None, remote_addr='127.0.0.1'):
        request = self.factory.post(reverse('login'), data or {})
        request.META['REMOTE_ADDR'] = remote_addr
        return request

    def _form(self, data=None, remote_addr='127.0.0.1'):
        payload = {
            'username': 'login-user',
            'password': 'safe-pass-123',
        }
        if data:
            payload.update(data)
        return BootstrapAuthenticationForm(request=self._request(payload, remote_addr), data=payload)

    def tearDown(self):
        cache.clear()

    def test_login_without_captcha_when_turnstile_not_configured(self):
        form = self._form()

        self.assertTrue(form.is_valid())

    @override_settings(TURNSTILE_SITE_KEY='site-key', TURNSTILE_SECRET_KEY='secret-key')
    def test_login_requires_captcha_when_turnstile_enabled(self):
        form = self._form({'captcha_token': ''})

        self.assertFalse(form.is_valid())
        self.assertIn('Complete the CAPTCHA challenge before logging in.', form.non_field_errors())

    @override_settings(TURNSTILE_SITE_KEY='site-key', TURNSTILE_SECRET_KEY='secret-key')
    @patch('app.forms.requests.post')
    def test_login_accepts_valid_turnstile_token(self, mock_post):
        mock_post.return_value.json.return_value = {'success': True}
        mock_post.return_value.raise_for_status.return_value = None

        form = self._form({'captcha_token': 'token-123'})

        self.assertTrue(form.is_valid())
        mock_post.assert_called_once()

    @override_settings(TURNSTILE_SITE_KEY='site-key', TURNSTILE_SECRET_KEY='secret-key')
    @patch('app.forms.requests.post', side_effect=RequestException('network down'))
    def test_login_rejects_when_turnstile_verification_unavailable(self, _mock_post):
        form = self._form({'captcha_token': 'token-123'})

        self.assertFalse(form.is_valid())
        self.assertIn('CAPTCHA verification is temporarily unavailable. Try again.', form.non_field_errors())

    @override_settings(TURNSTILE_SITE_KEY='site-key', TURNSTILE_SECRET_KEY='secret-key')
    @patch('app.forms.requests.post')
    def test_login_rejects_when_turnstile_verification_fails(self, mock_post):
        mock_post.return_value.json.return_value = {'success': False}
        mock_post.return_value.raise_for_status.return_value = None

        form = self._form({'captcha_token': 'token-123'})

        self.assertFalse(form.is_valid())
        self.assertIn('CAPTCHA verification failed. Try again.', form.non_field_errors())

    @override_settings(TURNSTILE_SITE_KEY='site-key', TURNSTILE_SECRET_KEY='secret-key', LOGIN_RATE_LIMIT_ATTEMPTS=0)
    @patch('app.forms.requests.post')
    def test_login_captcha_uses_forwarded_ip_and_rate_limit_can_be_disabled(self, mock_post):
        mock_post.return_value.json.return_value = {'success': True}
        mock_post.return_value.raise_for_status.return_value = None
        form = self._form({'captcha_token': 'token-123'})
        form.request.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.10, 10.0.0.1'

        self.assertTrue(form.is_valid())
        self.assertEqual(form._client_ip(), '203.0.113.10')
        self.assertIsNone(form._check_rate_limit('login-user'))
        self.assertEqual(mock_post.call_args.kwargs['data']['remoteip'], '203.0.113.10')

    def test_login_client_ip_without_request_is_unknown(self):
        form = BootstrapAuthenticationForm(request=None, data={'username': 'u', 'password': 'p'})

        self.assertEqual(form._client_ip(), 'unknown')

    @override_settings(LOGIN_RATE_LIMIT_ATTEMPTS=2, LOGIN_RATE_LIMIT_WINDOW_SECONDS=60)
    def test_login_rate_limit_blocks_after_threshold(self):
        first_form = self._form({'password': 'wrong-pass'})
        second_form = self._form({'password': 'wrong-pass'})
        blocked_form = self._form({'password': 'wrong-pass'})

        self.assertFalse(first_form.is_valid())
        self.assertIn('Please enter a correct username and password.', first_form.non_field_errors()[0])
        self.assertFalse(second_form.is_valid())
        self.assertIn('Please enter a correct username and password.', second_form.non_field_errors()[0])
        self.assertFalse(blocked_form.is_valid())
        self.assertIn('Too many login attempts. Try again in 1 minute(s).', blocked_form.non_field_errors())

    @override_settings(LOGIN_RATE_LIMIT_ATTEMPTS=3, LOGIN_RATE_LIMIT_WINDOW_SECONDS=60)
    def test_successful_login_clears_rate_limit_counter(self):
        failed_form = self._form({'password': 'wrong-pass'})
        successful_form = self._form()
        retry_form = self._form({'password': 'wrong-pass'})

        self.assertFalse(failed_form.is_valid())
        self.assertTrue(successful_form.is_valid())
        self.assertFalse(retry_form.is_valid())
        self.assertIn('Please enter a correct username and password.', retry_form.non_field_errors()[0])


class LoginPageRenderingTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        settings.SECRET_KEY = 'test-secret-key'

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_login_page_hides_turnstile_when_not_configured(self):
        response = self.client.get(reverse('login'))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'cf-turnstile')
        self.assertNotContains(response, 'id_captcha_token')

    @override_settings(
        SECURE_SSL_REDIRECT=False,
        TURNSTILE_SITE_KEY='site-key',
        TURNSTILE_SECRET_KEY='secret-key',
    )
    def test_login_page_renders_turnstile_when_configured(self):
        response = self.client.get(reverse('login'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'cf-turnstile')
        self.assertContains(response, 'data-sitekey="site-key"', html=False)
        self.assertContains(response, 'id_captcha_token')
        self.assertContains(response, 'challenges.cloudflare.com/turnstile/v0/api.js', html=False)


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
    def test_token_statuses_scoped_to_logged_in_user(self, _mock_status):
        request = self.factory.get(reverse('token_statuses'))
        request.user = self.user
        response = token_statuses(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertIn(self.user_account.zk_user_id, payload['statuses_by_id'])
        self.assertNotIn(self.other_account.zk_user_id, payload['statuses_by_id'])

    @patch('app.views._auth_status', return_value='active')
    def test_token_payload_includes_refresh_timestamp(self, _mock_status):
        request = self.factory.get(reverse('token_statuses'))
        request.user = self.user
        response = token_statuses(request)
        payload = json.loads(response.content)['statuses_by_id'][self.user_account.zk_user_id]

        self.assertEqual(payload['label'], 'Active')
        self.assertEqual(payload['css'], 'label-success')
        self.assertIn('checked_at', payload)
        self.assertIn('checked_at_display', payload)


class ConfigureZkAuthReauthTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='owner', password='owner-pass')
        self.kite_user = KiteUser.objects.create(
            owner=self.user,
            api_key='mode-api',
            api_secret='mode-secret',
            access_token='mode-token',
            user_name='Mode Kite',
            user_id='MD1234',
        )

    @patch('app.views._auth_status', return_value='active')
    @patch('app.views._kite_login_url', return_value='https://example.com/kite-login')
    def test_reauth_redirects_to_oauth_login(self, _mock_login_url, _mock_status):
        request = self.factory.get(reverse('configurezkauth') + '?reauth=' + self.kite_user.zk_user_id)
        request.user = self.user
        request.session = {}

        response = configurezkauth(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], 'https://example.com/kite-login')
        self.assertEqual(request.session.get('pending_zk_user_id'), self.kite_user.zk_user_id)


class ConfigureZkAuthEditApiCredentialsTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='owner-edit', password='owner-pass')
        self.other = User.objects.create_user(username='other-edit', password='other-pass')
        self.kite_user = KiteUser.objects.create(
            owner=self.user,
            api_key='owner-api',
            api_secret='owner-secret',
            access_token='owner-token',
            refresh_token='owner-refresh',
            user_name='Owner Kite',
            user_id='OW1234',
        )

    def _post(self, actor, payload):
        request = self.factory.post(reverse('configurezkauth'), payload)
        request.user = actor
        request.session = {}
        return configurezkauth(request)

    @patch('app.views._auth_status', return_value='active')
    def test_owner_can_edit_api_key_and_secret(self, _mock_status):
        response = self._post(self.user, {
            'action': 'edit_credentials',
            'zk_user_id': self.kite_user.zk_user_id,
            'api_key': 'owner-api-new',
            'api_secret': 'owner-secret-new',
        })
        self.assertEqual(response.status_code, 200)
        self.kite_user.refresh_from_db()
        self.assertEqual(self.kite_user.api_key, 'owner-api-new')
        self.assertEqual(self.kite_user.api_secret, 'owner-secret-new')
        self.assertEqual(self.kite_user.access_token, '')
        self.assertEqual(self.kite_user.refresh_token, '')

    @patch('app.views._auth_status', return_value='active')
    def test_owner_can_clear_api_key_and_secret(self, _mock_status):
        response = self._post(self.user, {
            'action': 'edit_credentials',
            'zk_user_id': self.kite_user.zk_user_id,
            'api_key': '',
            'api_secret': '',
            'clear_api_key': '1',
            'clear_api_secret': '1',
        })
        self.assertEqual(response.status_code, 200)
        self.kite_user.refresh_from_db()
        self.assertIsNone(self.kite_user.api_key)
        self.assertEqual(self.kite_user.api_secret, '')

    @patch('app.views._auth_status', return_value='active')
    def test_non_owner_cannot_edit(self, _mock_status):
        response = self._post(self.other, {
            'action': 'edit_credentials',
            'zk_user_id': self.kite_user.zk_user_id,
            'api_key': 'hijack',
            'api_secret': 'hijack-secret',
        })
        self.assertEqual(response.status_code, 302)
        self.kite_user.refresh_from_db()
        self.assertEqual(self.kite_user.api_key, 'owner-api')


class KiteLoginUrlNormalizationTests(TestCase):
    @patch('app.views._make_kite')
    def test_kite_trade_domain_is_normalized(self, mock_make_kite):
        class _MockKite:
            def login_url(self):
                return 'https://kite.trade/connect/login?v=3&api_key=abc'

        mock_make_kite.return_value = _MockKite()
        url = _kite_login_url('abc')
        self.assertEqual(url, 'https://kite.zerodha.com/connect/login?v=3&api_key=abc')

    @patch('app.views._make_kite')
    def test_non_kite_trade_domain_is_unchanged(self, mock_make_kite):
        class _MockKite:
            def login_url(self):
                return 'https://example.com/connect/login?v=3&api_key=abc'

        mock_make_kite.return_value = _MockKite()
        url = _kite_login_url('abc')
        self.assertEqual(url, 'https://example.com/connect/login?v=3&api_key=abc')


class TradePageRenderingTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='trade-owner', password='trade-pass')
        self.kite_user = KiteUser.objects.create(
            owner=self.user,
            api_key='trade-api',
            api_secret='trade-secret',
            access_token='trade-token',
            user_name='Trade Kite',
            user_id='TR1234',
        )

    @patch('app.views._auth_status', return_value='expired')
    @patch('app.views._trade_data_for_user', side_effect=KiteException('temporary failure'))
    def test_trade_sections_render_even_when_initial_fetch_fails(self, _mock_trade_data, _mock_auth_status):
        request = self.factory.get(reverse('trade') + '?api_key=' + self.kite_user.api_key)
        request.user = self.user

        response = trade(request)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="holdingsTable"')
        self.assertContains(response, 'id="positionsTable"')
        self.assertContains(response, 'id="openOrdersTable"')

    @patch('app.views._auth_status', return_value='expired')
    @patch('app.views._trade_data_for_user', side_effect=KiteException('temporary failure'))
    def test_holdings_table_includes_t1_and_used_quantity_columns(self, _mock_trade_data, _mock_auth_status):
        request = self.factory.get(reverse('trade') + '?api_key=' + self.kite_user.api_key)
        request.user = self.user

        response = trade(request)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<th>T1 Qty</th>', html=False)
        self.assertContains(response, '<th>Used Qty</th>', html=False)


class TradeDropdownScopingTests(TestCase):
    """The trade dropdown lists Kite users irrespective of token status,
    scoped by the logged-in user's role."""

    def setUp(self):
        self.factory = RequestFactory()
        self.owner = User.objects.create_user(username='scope-owner', password='pass')
        self.owner.profile.role = Profile.SELF_ONLY
        self.owner.profile.save()
        self.trader = User.objects.create_user(username='scope-trader', password='pass')
        self.trader.profile.role = Profile.TRADER_ALL
        self.trader.profile.save()

        # Own account WITHOUT a token (inactive) must still be listed.
        self.owner_tokenless = KiteUser.objects.create(
            owner=self.owner, api_key='own-tokenless-api', api_secret='s',
            access_token='', user_name='Own Tokenless', user_id='OT0001',
        )
        # Another app user's account, also tokenless.
        self.foreign_tokenless = KiteUser.objects.create(
            owner=self.trader, api_key='foreign-tokenless-api', api_secret='s',
            access_token='', user_name='Foreign Tokenless', user_id='FT0002',
        )

    def test_self_only_sees_only_own_users_regardless_of_token(self):
        request = self.factory.get(reverse('trade'))
        request.user = self.owner

        response = trade(request)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Own Tokenless')
        self.assertNotContains(response, 'Foreign Tokenless')

    def test_trader_all_sees_all_users_regardless_of_token(self):
        request = self.factory.get(reverse('trade'))
        request.user = self.trader

        response = trade(request)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Own Tokenless')
        self.assertContains(response, 'Foreign Tokenless')

    @patch('app.views._auth_status', return_value='none')
    @patch('app.views._trade_data_for_user', return_value={'open_orders': [], 'positions': []})
    def test_refresh_works_for_tokenless_selected_user(self, _mock_trade_data, _mock_status):
        request = self.factory.get(reverse('trade_refresh_data'), {'api_key': 'own-tokenless-api'})
        request.user = self.owner

        response = trade_refresh_data(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['api_key'], 'own-tokenless-api')
        self.assertEqual(payload['selected_status']['label'], 'Needs Authentication')

    def test_get_trade_user_finds_tokenless_account_scoped_by_role(self):
        # self_only owner can resolve their own tokenless account...
        self.assertEqual(
            _get_trade_user('own-tokenless-api', self.owner),
            self.owner_tokenless,
        )
        # ...but not another user's account.
        self.assertIsNone(_get_trade_user('foreign-tokenless-api', self.owner))
        # trader_all can resolve any tokenless account.
        self.assertEqual(
            _get_trade_user('foreign-tokenless-api', self.trader),
            self.foreign_tokenless,
        )


class KiteCallbackUrlTests(TestCase):
    """`_kite_callback_url` derives its scheme from DEBUG."""

    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(DEBUG=True)
    def test_debug_true_uses_request_scheme_and_host(self):
        request = self.factory.get('/configurezkauth/')
        url = _kite_callback_url(request)
        self.assertEqual(url, 'http://testserver' + reverse('kite_callback'))

    @override_settings(DEBUG=False)
    def test_debug_false_forces_https(self):
        request = self.factory.get('/configurezkauth/')
        url = _kite_callback_url(request)
        self.assertEqual(url, 'https://testserver' + reverse('kite_callback'))



class MarketProtectionTests(TestCase):
    class _KiteStub:
        def __init__(self, quote_payload):
            self.quote_payload = quote_payload
            self.last_place_kwargs = None

        def quote(self, key):
            return {key: self.quote_payload}

        def place_order(self, **kwargs):
            self.last_place_kwargs = kwargs
            return 'order-1'

    def test_market_order_sets_market_protection_to_one(self):
        kite = self._KiteStub({
            'last_price': 100,
            'circuit_limit': {'lower': 90, 'upper': 110},
        })
        order_id = _place(kite, {
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '1',
            'product': 'CNC',
            'order_type': 'MARKET',
        })

        self.assertEqual(order_id, 'order-1')
        self.assertEqual(kite.last_place_kwargs.get('market_protection'), 1)

    def test_limit_order_does_not_send_market_protection(self):
        kite = self._KiteStub({
            'last_price': 100,
            'circuit_limit': {'lower': 90, 'upper': 110},
        })
        order_id = _place(kite, {
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '1',
            'product': 'CNC',
            'order_type': 'LIMIT',
            'price': '100',
        })

        self.assertEqual(order_id, 'order-1')
        self.assertNotIn('market_protection', kite.last_place_kwargs)

    def test_limit_order_requires_price(self):
        kite = self._KiteStub({
            'last_price': 100,
            'circuit_limit': {'lower': 90, 'upper': 110},
        })
        with self.assertRaises(ValueError):
            _place(kite, {
                'exchange': 'NSE',
                'tradingsymbol': 'INFY',
                'transaction_type': 'BUY',
                'quantity': '1',
                'product': 'CNC',
                'order_type': 'LIMIT',
            })


class TradeModifyComplianceTests(TestCase):
    class _KiteModifyStub:
        def __init__(self):
            self.modify_kwargs = None

        def modify_order(self, **kwargs):
            self.modify_kwargs = kwargs

        def cancel_order(self, **kwargs):
            return None

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='modify-owner', password='modify-pass')

    @patch('app.views._user_kite')
    def test_modify_market_sets_market_protection_one(self, mock_user_kite):
        kite = self._KiteModifyStub()
        mock_user_kite.return_value = kite

        request = self.factory.post(reverse('trade_modify'), {
            'api_key': 'k',
            'order_id': 'OID1',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '2',
            'order_type': 'MARKET',
        })
        request.user = self.user

        response = trade_modify(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kite.modify_kwargs.get('market_protection'), 1)
        self.assertNotIn('price', kite.modify_kwargs)

    @patch('app.views._user_kite')
    def test_modify_limit_requires_price(self, mock_user_kite):
        kite = self._KiteModifyStub()
        mock_user_kite.return_value = kite

        request = self.factory.post(reverse('trade_modify'), {
            'api_key': 'k',
            'order_id': 'OID2',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '2',
            'order_type': 'LIMIT',
            'price': '',
        })
        request.user = self.user

        response = trade_modify(request)

        self.assertEqual(response.status_code, 302)
        self.assertIsNone(kite.modify_kwargs)


class TradeConvertPositionTests(TestCase):
    class _KiteConvertStub:
        def __init__(self):
            self.convert_kwargs = None

        def convert_position(self, **kwargs):
            self.convert_kwargs = kwargs
            return True

    class _KiteConvertFailStub:
        def convert_position(self, **kwargs):
            raise KiteException('conversion rejected')

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='convert-owner', password='convert-pass')

    def _post(self, payload):
        request = self.factory.post(reverse('trade_convert_position'), payload)
        request.user = self.user
        return request

    def test_normalize_product_maps_nrml_to_cnc(self):
        self.assertEqual(_normalize_product('NRML'), 'CNC')
        self.assertEqual(_normalize_product('nrml'), 'CNC')
        self.assertEqual(_normalize_product(' mis '), 'MIS')
        self.assertEqual(_normalize_product(None), '')

    @patch('app.views._user_kite')
    def test_convert_position_success_passes_expected_kwargs(self, mock_user_kite):
        kite = self._KiteConvertStub()
        mock_user_kite.return_value = kite

        response = trade_convert_position(self._post({
            'api_key': 'k',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'position_type': 'day',
            'quantity': '3',
            'old_product': 'CNC',
            'new_product': 'MIS',
        }))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kite.convert_kwargs, {
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'position_type': 'day',
            'quantity': 3,
            'old_product': 'CNC',
            'new_product': 'MIS',
        })
        self.assertIn('level=success', response['Location'])

    @patch('app.views._user_kite')
    def test_convert_position_normalizes_nrml_to_cnc(self, mock_user_kite):
        kite = self._KiteConvertStub()
        mock_user_kite.return_value = kite

        response = trade_convert_position(self._post({
            'api_key': 'k',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'SELL',
            'position_type': 'overnight',
            'quantity': '5',
            'old_product': 'MIS',
            'new_product': 'NRML',
        }))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kite.convert_kwargs['old_product'], 'MIS')
        self.assertEqual(kite.convert_kwargs['new_product'], 'CNC')
        self.assertEqual(kite.convert_kwargs['position_type'], 'overnight')

    @patch('app.views._user_kite', return_value=None)
    def test_convert_position_without_authenticated_user_redirects_error(self, _mock_user_kite):
        response = trade_convert_position(self._post({
            'api_key': 'k',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '1',
            'old_product': 'CNC',
            'new_product': 'MIS',
        }))

        self.assertEqual(response.status_code, 302)
        self.assertIn('level=error', response['Location'])

    @patch('app.views._user_kite')
    def test_convert_position_rejects_non_positive_quantity(self, mock_user_kite):
        kite = self._KiteConvertStub()
        mock_user_kite.return_value = kite

        response = trade_convert_position(self._post({
            'api_key': 'k',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '0',
            'old_product': 'CNC',
            'new_product': 'MIS',
        }))

        self.assertEqual(response.status_code, 302)
        self.assertIn('level=error', response['Location'])
        self.assertIsNone(kite.convert_kwargs)

    @patch('app.views._user_kite')
    def test_convert_position_rejects_same_products(self, mock_user_kite):
        kite = self._KiteConvertStub()
        mock_user_kite.return_value = kite

        response = trade_convert_position(self._post({
            'api_key': 'k',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '2',
            'old_product': 'NRML',
            'new_product': 'CNC',
        }))

        self.assertEqual(response.status_code, 302)
        self.assertIn('level=error', response['Location'])
        self.assertIsNone(kite.convert_kwargs)

    @patch('app.views._user_kite')
    def test_convert_position_rejects_invalid_transaction_type(self, mock_user_kite):
        kite = self._KiteConvertStub()
        mock_user_kite.return_value = kite

        response = trade_convert_position(self._post({
            'api_key': 'k',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'HOLD',
            'quantity': '2',
            'old_product': 'CNC',
            'new_product': 'MIS',
        }))

        self.assertEqual(response.status_code, 302)
        self.assertIn('level=error', response['Location'])
        self.assertIsNone(kite.convert_kwargs)

    @patch('app.views._user_kite')
    def test_convert_position_handles_kite_exception(self, mock_user_kite):
        mock_user_kite.return_value = self._KiteConvertFailStub()

        response = trade_convert_position(self._post({
            'api_key': 'k',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '2',
            'old_product': 'CNC',
            'new_product': 'MIS',
        }))

        self.assertEqual(response.status_code, 302)
        self.assertIn('level=error', response['Location'])


class TradePositionsConvertRenderingTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='pos-owner', password='pos-pass')
        self.kite_user = KiteUser.objects.create(
            owner=self.user,
            api_key='pos-api',
            api_secret='pos-secret',
            access_token='pos-token',
            user_name='Pos Kite',
            user_id='PS1234',
        )

    @patch('app.views._auth_status', return_value='active')
    @patch('app.views._trade_data_for_user')
    def test_positions_row_renders_convert_button(self, mock_trade_data, _mock_status):
        data = _empty_trade_data()
        data['positions'] = [{
            'tradingsymbol': 'INFY', 'exchange': 'NSE', 'product': 'MIS',
            'quantity': 3, 'average_price': 100, 'last_price': 101, 'pnl': 3,
        }]
        mock_trade_data.return_value = data

        request = self.factory.get(reverse('trade') + '?api_key=' + self.kite_user.api_key)
        request.user = self.user

        response = trade(request)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'onclick="convertPosition(this)"', html=False)
        self.assertContains(response, 'id="convertModal"', html=False)
        self.assertContains(response, 'data-sym="INFY"', html=False)


class TradeDataResilienceTests(TestCase):
    class _KitePartialStub:
        def profile(self):
            return {'user_name': 'Trader', 'email': 'trader@example.com'}

        def orders(self):
            raise KiteException('orders unavailable')

        def margins(self):
            return {'equity': {'available': {'cash': 1000}}}

        def holdings(self):
            return [{'tradingsymbol': 'INFY', 'pnl': 42}]

        def positions(self):
            return {'net': [{'tradingsymbol': 'SBIN', 'quantity': 1, 'average_price': 100, 'last_price': 101, 'pnl': 1}]}

    @patch('app.views._call_with_token_renewal')
    def test_trade_data_survives_partial_api_failures(self, mock_call):
        kite = self._KitePartialStub()
        mock_call.side_effect = lambda _user, operation: operation(kite)

        data = _trade_data_for_user(object())

        self.assertEqual(data['profile']['user_name'], 'Trader')
        self.assertEqual(data['open_orders'], [])
        self.assertEqual(len(data['holdings']), 1)
        self.assertEqual(len(data['positions']), 1)


class ModelAndAdminBehaviorTests(TestCase):
    def test_generate_identifier_and_model_strings(self):
        identifier = generate_kite_user_identifier()
        user = User.objects.create_user(username='model-user', password='model-pass')
        kite_user = KiteUser.objects.create(owner=user, api_key='model-api', user_name='Model Kite')

        self.assertTrue(identifier.startswith('ZK'))
        self.assertEqual(len(identifier), 14)
        self.assertEqual(str(user.profile), 'model-user (self_only)')
        self.assertEqual(str(kite_user), '{0} (Model Kite)'.format(kite_user.zk_user_id))

    def test_user_creation_auto_creates_profile_and_admin_role_display(self):
        user = User.objects.create_user(username='profile-user', password='profile-pass')
        user.profile.role = Profile.ADMIN_ONLY
        user.profile.save()
        admin_view = UserWithRoleAdmin(User, admin.site)

        self.assertEqual(user.profile.role, Profile.ADMIN_ONLY)
        self.assertEqual(admin_view.get_role(user), Profile.ADMIN_ONLY)


class PermissionAndTokenHelperTests(TestCase):
    def setUp(self):
        self.self_user = User.objects.create_user(username='self-user', password='self-pass')
        self.admin_user = User.objects.create_user(username='admin-user', password='admin-pass')
        self.trader_user = User.objects.create_user(username='trader-user', password='trader-pass')
        self.admin_user.profile.role = Profile.ADMIN_ONLY
        self.admin_user.profile.save()
        self.trader_user.profile.role = Profile.TRADER_ALL
        self.trader_user.profile.save()

    def test_role_helper_permissions(self):
        self.assertFalse(is_admin(self.self_user))
        self.assertTrue(is_admin(self.admin_user))
        self.assertFalse(can_trade_all(self.self_user))
        self.assertTrue(can_trade_all(self.admin_user))
        self.assertTrue(can_trade_all(self.trader_user))
        self.assertTrue(can_configure_accounts(self.self_user))
        self.assertTrue(can_configure_accounts(self.admin_user))
        self.assertFalse(can_configure_accounts(self.trader_user))

    def test_persist_token_data_updates_nested_payload_fields(self):
        kite_user = KiteUser.objects.create(owner=self.self_user, api_key='persist-api')

        _persist_token_data(kite_user, {
            'access_token': 'access-1',
            'refresh_token': 'refresh-1',
            'data': {
                'user_id': 'AB1234',
                'user_name': 'Persisted User',
                'email': 'persist@example.com',
            },
        })
        kite_user.refresh_from_db()

        self.assertEqual(kite_user.access_token, 'access-1')
        self.assertEqual(kite_user.refresh_token, 'refresh-1')
        self.assertEqual(kite_user.user_id, 'AB1234')
        self.assertEqual(kite_user.user_name, 'Persisted User')
        self.assertEqual(kite_user.email, 'persist@example.com')

    @patch('app.views._make_kite')
    def test_renew_access_token_updates_user(self, mock_make_kite):
        kite_user = KiteUser.objects.create(
            owner=self.self_user,
            api_key='renew-api',
            api_secret='renew-secret',
            refresh_token='refresh-abc',
        )
        mock_make_kite.return_value.renew_access_token.return_value = {
            'access_token': 'new-access',
            'refresh_token': 'new-refresh',
            'user_name': 'Renewed User',
        }

        renewed = _renew_access_token(kite_user)
        kite_user.refresh_from_db()

        self.assertTrue(renewed)
        self.assertEqual(kite_user.access_token, 'new-access')
        self.assertEqual(kite_user.refresh_token, 'new-refresh')
        self.assertEqual(kite_user.user_name, 'Renewed User')

    def test_renew_access_token_returns_false_without_required_credentials(self):
        missing_refresh = KiteUser.objects.create(owner=self.self_user, api_key='no-refresh', api_secret='secret', refresh_token='')
        missing_secret = KiteUser.objects.create(owner=self.self_user, api_key='no-secret', api_secret='', refresh_token='refresh')

        self.assertFalse(_renew_access_token(missing_refresh))
        self.assertFalse(_renew_access_token(missing_secret))

    @patch('app.views._make_kite')
    def test_renew_access_token_returns_false_when_no_access_token_is_returned(self, mock_make_kite):
        kite_user = KiteUser.objects.create(
            owner=self.self_user,
            api_key='renew-empty-api',
            api_secret='renew-secret',
            refresh_token='refresh-abc',
        )
        mock_make_kite.return_value.renew_access_token.return_value = {
            'refresh_token': 'new-refresh',
        }

        renewed = _renew_access_token(kite_user)
        kite_user.refresh_from_db()

        self.assertFalse(renewed)
        self.assertEqual(kite_user.access_token, '')
        self.assertEqual(kite_user.refresh_token, 'new-refresh')

    @patch('app.views._renew_access_token', return_value=True)
    @patch('app.views._make_kite')
    def test_call_with_token_renewal_retries_after_token_exception(self, mock_make_kite, _mock_renew):
        kite_user = KiteUser.objects.create(owner=self.self_user, api_key='retry-api', access_token='old-token')
        first_kite = object()
        second_kite = object()
        mock_make_kite.side_effect = [first_kite, second_kite]
        calls = []

        def operation(kite):
            calls.append(kite)
            if len(calls) == 1:
                raise TokenException('expired')
            return 'ok'

        result = _call_with_token_renewal(kite_user, operation)

        self.assertEqual(result, 'ok')
        self.assertEqual(calls, [first_kite, second_kite])

    @patch('app.views._renew_access_token', return_value=False)
    @patch('app.views._make_kite')
    def test_call_with_token_renewal_reraises_when_refresh_fails(self, mock_make_kite, _mock_renew):
        kite_user = KiteUser.objects.create(owner=self.self_user, api_key='retry-fail-api', access_token='old-token')
        mock_make_kite.return_value = object()

        def operation(_kite):
            raise TokenException('expired')

        with self.assertRaises(TokenException):
            _call_with_token_renewal(kite_user, operation)

    def test_auth_status_variants(self):
        kite_user = KiteUser.objects.create(owner=self.self_user, api_key='auth-api', access_token='token')
        no_token_user = KiteUser.objects.create(owner=self.self_user, api_key='auth-none', access_token='')

        self.assertEqual(_auth_status(no_token_user), 'none')
        with patch('app.views._call_with_token_renewal', return_value={'user_id': 'AB12'}):
            self.assertEqual(_auth_status(kite_user), 'active')
        with patch('app.views._call_with_token_renewal', side_effect=TokenException('expired')):
            self.assertEqual(_auth_status(kite_user), 'expired')
        with patch('app.views._call_with_token_renewal', side_effect=KiteException('broken')):
            self.assertEqual(_auth_status(kite_user), 'error')

    @patch('app.views.KiteConnect')
    def test_make_kite_sets_access_token_when_provided(self, mock_kiteconnect):
        kite = mock_kiteconnect.return_value

        result = _make_kite('api-key', 'access-token')

        self.assertEqual(result, kite)
        mock_kiteconnect.assert_called_once_with(api_key='api-key')
        kite.set_access_token.assert_called_once_with('access-token')


class ManageZkUsersFlowTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.admin_user = User.objects.create_superuser(username='super', email='super@example.com', password='super-pass')
        self.target_user = User.objects.create_user(username='target-user', password='target-pass')

    def test_admin_can_add_app_user(self):
        request = self.factory.post(reverse('managezkusers'), {
            'username': 'new-user',
            'password': 'new-pass-123',
            'role': Profile.TRADER_ALL,
        })
        request.user = self.admin_user

        response = managezkusers(request)

        self.assertEqual(response.status_code, 200)
        created_user = User.objects.get(username='new-user')
        self.assertEqual(created_user.profile.role, Profile.TRADER_ALL)

    def test_admin_can_edit_existing_user(self):
        request = self.factory.post(reverse('managezkusers'), {
            'action': 'edit',
            'user_id': self.target_user.id,
            'password': 'changed-pass-123',
            'role': Profile.ADMIN_ONLY,
        })
        request.user = self.admin_user

        response = managezkusers(request)
        self.target_user.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.target_user.profile.role, Profile.ADMIN_ONLY)
        self.assertTrue(self.target_user.check_password('changed-pass-123'))

    def test_admin_cannot_delete_superuser(self):
        request = self.factory.post(reverse('managezkusers'), {
            'action': 'delete',
            'user_id': self.admin_user.id,
        })
        request.user = self.admin_user

        response = managezkusers(request)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(User.objects.filter(id=self.admin_user.id).exists())

    def test_admin_sees_user_not_found_messages_for_missing_targets(self):
        delete_request = self.factory.post(reverse('managezkusers'), {
            'action': 'delete',
            'user_id': 999999,
        })
        delete_request.user = self.admin_user
        delete_response = managezkusers(delete_request)

        edit_request = self.factory.post(reverse('managezkusers'), {
            'action': 'edit',
            'user_id': 999999,
            'role': Profile.ADMIN_ONLY,
        })
        edit_request.user = self.admin_user
        edit_response = managezkusers(edit_request)

        self.assertEqual(delete_response.status_code, 200)
        self.assertContains(delete_response, 'User not found.')
        self.assertEqual(edit_response.status_code, 200)
        self.assertContains(edit_response, 'User not found.')

    def test_admin_cannot_edit_superuser(self):
        request = self.factory.post(reverse('managezkusers'), {
            'action': 'edit',
            'user_id': self.admin_user.id,
            'password': 'new-super-pass',
            'role': Profile.ADMIN_ONLY,
        })
        request.user = self.admin_user

        response = managezkusers(request)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Cannot modify superuser accounts.')


class KiteCallbackFlowTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='callback-owner', password='callback-pass')
        self.other = User.objects.create_user(username='callback-other', password='other-pass')
        self.kite_user = KiteUser.objects.create(
            owner=self.user,
            api_key='callback-api',
            api_secret='callback-secret',
        )

    @patch('app.views._sync_profile_from_kite')
    @patch('app.views._make_kite')
    def test_kite_callback_persists_generated_session(self, mock_make_kite, mock_sync_profile):
        mock_make_kite.return_value.generate_session.return_value = {
            'access_token': 'callback-access',
            'refresh_token': 'callback-refresh',
            'user_name': 'Callback User',
            'user_id': 'CB1234',
        }
        request = self.factory.get(reverse('kite_callback'), {'request_token': 'req-1', 'status': 'success'})
        request.user = self.user
        request.session = {'pending_zk_user_id': self.kite_user.zk_user_id}

        response = kite_callback(request)
        self.kite_user.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.kite_user.access_token, 'callback-access')
        self.assertEqual(self.kite_user.refresh_token, 'callback-refresh')
        self.assertEqual(self.kite_user.user_name, 'Callback User')
        mock_sync_profile.assert_called_once_with(self.kite_user)
        self.assertNotIn('pending_zk_user_id', request.session)

    def test_kite_callback_redirects_for_wrong_owner(self):
        request = self.factory.get(reverse('kite_callback'), {'request_token': 'req-1', 'status': 'success'})
        request.user = self.other
        request.session = {'pending_zk_user_id': self.kite_user.zk_user_id}

        response = kite_callback(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], reverse('configurezkauth'))


class NumericAndNormalizationHelperTests(TestCase):
    def test_scalar_value_sum_margin_and_position_normalization(self):
        self.assertEqual(_scalar_value('42'), 42)
        self.assertEqual(_scalar_value({'value': '7.5'}), 7.5)
        self.assertEqual(_scalar_value(['9']), 9)
        self.assertEqual(_scalar_value('ABC'), 'ABC')
        self.assertEqual(_sum_numeric_values({'a': 1, 'b': {'c': '2.5'}}), 3.5)
        self.assertIsNone(_sum_numeric_values('not-a-number'))
        self.assertEqual(
            _calculate_margin_used({'equity': {'utilised': {'debits': 10}}, 'commodity': {'used': {'x': 5.5}}}),
            15.5,
        )
        self.assertEqual(
            _normalize_position({'net_quantity': '2', 'avg_price': '101.25', 'tradingsymbol': 'INFY'}),
            {'net_quantity': '2', 'avg_price': '101.25', 'tradingsymbol': 'INFY', 'quantity': 2, 'average_price': 101.25},
        )


class TradeRefreshAndDeleteFlowTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.owner = User.objects.create_user(username='refresh-owner', password='refresh-pass')
        self.admin_user = User.objects.create_user(username='refresh-admin', password='refresh-admin-pass')
        self.admin_user.profile.role = Profile.ADMIN_ONLY
        self.admin_user.profile.save()
        self.other = User.objects.create_user(username='refresh-other', password='other-pass')
        self.owner_account = KiteUser.objects.create(owner=self.owner, api_key='owner-api', access_token='owner-token')
        self.other_account = KiteUser.objects.create(owner=self.other, api_key='other-api', access_token='other-token')

    def test_trade_refresh_missing_api_key_returns_400(self):
        request = self.factory.get(reverse('trade_refresh_data'))
        request.user = self.owner

        response = trade_refresh_data(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)['error'], 'Missing api_key.')

    def test_trade_refresh_all_requires_elevated_role(self):
        request = self.factory.get(reverse('trade_refresh_data'), {'api_key': 'all', 'selected_api_key': 'owner-api'})
        request.user = self.owner

        response = trade_refresh_data(request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content)['error'], 'Not authorized to refresh all accounts.')

    @patch('app.views._auth_status', return_value='active')
    @patch('app.views._trade_data_for_user', return_value={'positions': [], 'open_orders': []})
    def test_trade_refresh_all_returns_selected_user_payload(self, _mock_trade_data, _mock_status):
        request = self.factory.get(reverse('trade_refresh_data'), {'api_key': 'all', 'selected_api_key': 'owner-api'})
        request.user = self.admin_user

        response = trade_refresh_data(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['api_key'], 'owner-api')
        self.assertEqual(payload['selected_status']['label'], 'Active')

    def test_deletezkuser_post_only_deletes_owned_account_for_self_user(self):
        request = self.factory.post(reverse('deletezkuser'), {'api_key': 'other-api'})
        request.user = self.owner

        response = deletezkuser(request)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(KiteUser.objects.filter(api_key='other-api').exists())
        self.assertTrue(KiteUser.objects.filter(api_key='owner-api').exists())


class MarketDataEndpointTests(TestCase):
    class _InstrumentKiteStub:
        def __init__(self):
            self.calls = []

        def instruments(self, exchange):
            self.calls.append(exchange)
            return [{'tradingsymbol': 'INFY', 'name': 'Infosys'}, {'tradingsymbol': 'INFIBEAM', 'name': 'Infibeam'}] * 11

    class _QuoteKiteStub:
        def __init__(self, should_fail=False):
            self.should_fail = should_fail

        def quote(self, key):
            if self.should_fail:
                raise KiteException('quote unavailable')
            return {key: {'last_price': 101.2, 'circuit_limit': {'lower': 90, 'upper': 110}}}

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='market-user', password='market-pass')
        self.kite_user = KiteUser.objects.create(owner=self.user, api_key='market-api', access_token='market-token')
        _INSTRUMENTS_CACHE.clear()

    def tearDown(self):
        _INSTRUMENTS_CACHE.clear()

    @patch('app.views._call_with_token_renewal', side_effect=TokenException('expired'))
    def test_user_kite_returns_none_on_token_exception(self, _mock_call):
        self.assertIsNone(_user_kite('market-api', self.user))

    @patch('app.views._user_kite')
    def test_instruments_search_limits_results(self, mock_user_kite):
        mock_user_kite.return_value = self._InstrumentKiteStub()
        request = self.factory.get(reverse('instruments_search'), {'api_key': 'market-api', 'q': 'INF', 'exchange': 'NSE'})
        request.user = self.user

        response = instruments_search(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(payload['results']), 20)

    @patch('app.views._user_kite')
    def test_instruments_all_returns_both_exchanges(self, mock_user_kite):
        mock_user_kite.return_value = self._InstrumentKiteStub()
        request = self.factory.get(reverse('instruments_all'), {'api_key': 'market-api'})
        request.user = self.user

        response = instruments_all(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(item['exchange'] == 'NSE' for item in payload['results']))
        self.assertTrue(any(item['exchange'] == 'BSE' for item in payload['results']))

    @patch('app.views._user_kite')
    def test_quote_returns_market_data(self, mock_user_kite):
        mock_user_kite.return_value = self._QuoteKiteStub()
        request = self.factory.get(reverse('quote'), {'api_key': 'market-api', 'symbol': 'INFY', 'exchange': 'NSE'})
        request.user = self.user

        response = quote(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['last_price'], 101.2)
        self.assertEqual(payload['lower'], 90)
        self.assertEqual(payload['upper'], 110)

    @patch('app.views._user_kite')
    def test_quote_surfaces_kite_errors(self, mock_user_kite):
        mock_user_kite.return_value = self._QuoteKiteStub(should_fail=True)
        request = self.factory.get(reverse('quote'), {'api_key': 'market-api', 'symbol': 'INFY', 'exchange': 'NSE'})
        request.user = self.user

        response = quote(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(payload['ok'])
        self.assertEqual(payload['error'], 'quote unavailable')

    def test_validate_circuit_rejects_outside_band_and_ignores_non_limit(self):
        class _BandKite:
            def quote(self, key):
                return {key: {'circuit_limit': {'lower': 90, 'upper': 110}}}

        class _BrokenBandKite:
            def quote(self, key):
                raise KiteException('broken')

        self.assertEqual(
            _validate_circuit(_BandKite(), 'NSE', 'INFY', 'LIMIT', 120),
            'Price 120 is outside circuit band 90-110.',
        )
        self.assertIsNone(_validate_circuit(_BandKite(), 'NSE', 'INFY', 'MARKET', None))
        self.assertIsNone(_validate_circuit(_BrokenBandKite(), 'NSE', 'INFY', 'LIMIT', 100))


class ContextProcessorAndMiddlewareTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.self_user = User.objects.create_user(username='ctx-self', password='ctx-pass')
        self.admin_user = User.objects.create_user(username='ctx-admin', password='ctx-pass')
        self.admin_user.profile.role = Profile.ADMIN_ONLY
        self.admin_user.profile.save()
        self.trader_user = User.objects.create_user(username='ctx-trader', password='ctx-pass')
        self.trader_user.profile.role = Profile.TRADER_ALL
        self.trader_user.profile.save()

    def test_user_role_context_for_anonymous_admin_and_trader(self):
        anonymous_request = self.factory.get('/')
        anonymous_request.user = type('AnonymousUser', (), {'is_authenticated': False})()
        admin_request = self.factory.get('/')
        admin_request.user = self.admin_user
        trader_request = self.factory.get('/')
        trader_request.user = self.trader_user

        self.assertEqual(user_role(anonymous_request), {})
        self.assertEqual(user_role(admin_request)['app_role'], 'Admin')
        self.assertTrue(user_role(admin_request)['app_can_trade_all'])
        self.assertEqual(user_role(trader_request)['app_role'], 'Trader all')
        self.assertFalse(user_role(trader_request)['app_can_configure'])

    def test_login_required_middleware_redirects_private_and_allows_public(self):
        middleware = LoginRequiredMiddleware(lambda request: type('Response', (), {'status_code': 200})())
        private_request = self.factory.get('/trade/')
        private_request.user = type('AnonymousUser', (), {'is_authenticated': False})()
        public_request = self.factory.get(reverse('login'))
        public_request.user = type('AnonymousUser', (), {'is_authenticated': False})()

        private_response = middleware(private_request)
        public_response = middleware(public_request)

        self.assertEqual(private_response.status_code, 302)
        self.assertEqual(private_response.url, reverse('login'))
        self.assertEqual(public_response.status_code, 200)


class AdditionalConfigureAndCallbackTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='extra-owner', password='extra-pass')
        self.admin_user = User.objects.create_user(username='extra-admin', password='extra-admin-pass')
        self.admin_user.profile.role = Profile.ADMIN_ONLY
        self.admin_user.profile.save()
        self.other = User.objects.create_user(username='extra-other', password='extra-other-pass')
        self.kite_user = KiteUser.objects.create(owner=self.user, api_key='extra-api', api_secret='extra-secret', access_token='tok')
        self.other_kite_user = KiteUser.objects.create(owner=self.other, api_key='other-extra-api', api_secret='other-secret', access_token='tok2')

    @patch('app.views._auth_status', return_value='active')
    def test_configurezkauth_duplicate_api_key_for_non_admin_is_rejected(self, _mock_status):
        request = self.factory.post(reverse('configurezkauth'), {
            'zerodha_username': 'AB1234',
            'api_key': 'other-extra-api',
            'api_secret': 'new-secret',
        })
        request.user = self.user
        request.session = {}

        response = configurezkauth(request)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'This API key is already configured for another app user.')

    @patch('app.views._auth_status', return_value='active')
    def test_configurezkauth_invalid_edit_request_shows_error(self, _mock_status):
        request = self.factory.post(reverse('configurezkauth'), {
            'action': 'edit_credentials',
            'zk_user_id': '',
        })
        request.user = self.user
        request.session = {}

        response = configurezkauth(request)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid edit request. Please review the entered fields.')

    @patch('app.views._auth_status', return_value='active')
    def test_configurezkauth_edit_noop_still_succeeds_without_clearing_tokens(self, _mock_status):
        self.kite_user.access_token = 'keep-token'
        self.kite_user.refresh_token = 'keep-refresh'
        self.kite_user.save()
        request = self.factory.post(reverse('configurezkauth'), {
            'action': 'edit_credentials',
            'zk_user_id': self.kite_user.zk_user_id,
            'api_key': self.kite_user.api_key,
            'api_secret': '',
        })
        request.user = self.user
        request.session = {}

        response = configurezkauth(request)
        self.kite_user.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'API credentials updated successfully')
        self.assertEqual(self.kite_user.access_token, 'keep-token')
        self.assertEqual(self.kite_user.refresh_token, 'keep-refresh')

    @patch('app.views._auth_status', return_value='active')
    def test_configurezkauth_reauth_redirects_when_secret_missing(self, _mock_status):
        self.kite_user.api_secret = ''
        self.kite_user.save()
        request = self.factory.get(reverse('configurezkauth'), {'reauth': self.kite_user.zk_user_id})
        request.user = self.user
        request.session = {}

        response = configurezkauth(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], reverse('configurezkauth'))

    def test_kite_callback_covers_error_messages(self):
        request = self.factory.get(reverse('kite_callback'), {'status': 'cancelled'})
        request.user = self.user
        request.session = {}
        response = kite_callback(request)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Kite login was not successful: cancelled')

        request = self.factory.get(reverse('kite_callback'), {'status': 'success'})
        request.user = self.user
        request.session = {}
        response = kite_callback(request)
        self.assertContains(response, 'Missing request_token in redirect.')

        request = self.factory.get(reverse('kite_callback'), {'request_token': 'req-1', 'status': 'success'})
        request.user = self.user
        request.session = {}
        response = kite_callback(request)
        self.assertContains(response, 'No pending user to authenticate. Start from Configure ZK Auth.')

    @patch('app.views._auth_status', return_value='active')
    @patch('app.views._kite_login_url', return_value='https://example.com/reauth')
    def test_admin_can_reauth_other_users_account(self, _mock_login_url, _mock_status):
        request = self.factory.get(reverse('configurezkauth'), {'reauth': self.other_kite_user.zk_user_id})
        request.user = self.admin_user
        request.session = {}

        response = configurezkauth(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], 'https://example.com/reauth')
        self.assertEqual(request.session['pending_zk_user_id'], self.other_kite_user.zk_user_id)

    @patch('app.views._make_kite')
    def test_kite_callback_handles_missing_user_and_kite_exception(self, mock_make_kite):
        request = self.factory.get(reverse('kite_callback'), {'request_token': 'req-1', 'status': 'success', 'api_key': 'missing'})
        request.user = self.user
        request.session = {}
        response = kite_callback(request)
        self.assertContains(response, 'No stored user for that API key.')

        mock_make_kite.return_value.generate_session.side_effect = KiteException('bad token')
        request = self.factory.get(reverse('kite_callback'), {'request_token': 'req-1', 'status': 'success'})
        request.user = self.user
        request.session = {'pending_zk_user_id': self.kite_user.zk_user_id}
        response = kite_callback(request)
        self.assertContains(response, 'Authentication failed: bad token')


class AdditionalTradeFlowTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='order-owner', password='order-pass')
        self.kite_user = KiteUser.objects.create(owner=self.user, api_key='order-api', access_token='order-token')

    def test_trade_refresh_requires_selected_api_key_for_all(self):
        admin_user = User.objects.create_user(username='order-admin', password='admin-pass')
        admin_user.profile.role = Profile.ADMIN_ONLY
        admin_user.profile.save()
        request = self.factory.get(reverse('trade_refresh_data'), {'api_key': 'all'})
        request.user = admin_user

        response = trade_refresh_data(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)['error'], 'Missing selected_api_key for current trade view.')

    @patch('app.views._make_kite')
    @patch('app.views._call_with_token_renewal', side_effect=KiteException('temporary'))
    def test_user_kite_returns_client_on_non_token_exception(self, _mock_call, mock_make_kite):
        mock_make_kite.return_value = 'kite-client'

        kite = _user_kite('order-api', self.user)

        self.assertEqual(kite, 'kite-client')

    @patch('app.views._user_kite', return_value=None)
    def test_trade_place_and_cancel_reject_missing_authenticated_user(self, _mock_user_kite):
        place_request = self.factory.post(reverse('trade_place'), {'api_key': 'order-api'})
        place_request.user = self.user
        place_response = trade_place(place_request)

        cancel_request = self.factory.post(reverse('trade_cancel'), {'api_key': 'order-api', 'order_id': 'OID1'})
        cancel_request.user = self.user
        cancel_response = trade_cancel(cancel_request)

        self.assertEqual(place_response.status_code, 302)
        self.assertIn('No+authenticated+user+selected.', place_response['Location'])
        self.assertEqual(cancel_response.status_code, 302)
        self.assertIn('No+authenticated+user+selected.', cancel_response['Location'])

    @patch('app.views._user_kite')
    def test_trade_cancel_and_modify_error_branches(self, mock_user_kite):
        class _BrokenKite:
            def cancel_order(self, **kwargs):
                raise KiteException('cancel failed')

            def modify_order(self, **kwargs):
                raise KiteException('modify failed')

        mock_user_kite.return_value = _BrokenKite()

        cancel_request = self.factory.post(reverse('trade_cancel'), {'api_key': 'order-api', 'order_id': 'OID1'})
        cancel_request.user = self.user
        cancel_response = trade_cancel(cancel_request)
        self.assertIn('Cancel+failed%3A+cancel+failed', cancel_response['Location'])

        modify_request = self.factory.post(reverse('trade_modify'), {
            'api_key': 'order-api',
            'order_id': 'OID1',
            'quantity': '1',
            'order_type': 'MARKET',
        })
        modify_request.user = self.user
        modify_response = trade_modify(modify_request)
        self.assertIn('Modify+failed%3A+modify+failed', modify_response['Location'])

    @patch('app.views._place')
    @patch('app.views._user_kite')
    def test_trade_modify_exchange_change_branch(self, mock_user_kite, mock_place):
        class _ExchangeKite:
            def __init__(self):
                self.cancelled = False

            def cancel_order(self, **kwargs):
                self.cancelled = True

        kite = _ExchangeKite()
        mock_user_kite.return_value = kite
        request = self.factory.post(reverse('trade_modify'), {
            'api_key': 'order-api',
            'order_id': 'OID1',
            'exchange': 'NSE',
            'new_exchange': 'BSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '1',
            'order_type': 'MARKET',
        })
        request.user = self.user

        response = trade_modify(request)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(kite.cancelled)
        mock_place.assert_called_once()
        self.assertIn('Order+cancelled+and+re-placed+on+new+exchange.', response['Location'])

    def test_instruments_search_returns_empty_without_query(self):
        request = self.factory.get(reverse('instruments_search'), {'api_key': 'order-api', 'q': ''})
        request.user = self.user
        with patch('app.views._user_kite', return_value=object()), patch('app.views._get_instruments', return_value=[]):
            response = instruments_search(request)

        self.assertEqual(json.loads(response.content), {'results': []})

    def test_quote_returns_false_without_symbol(self):
        request = self.factory.get(reverse('quote'), {'api_key': 'order-api'})
        request.user = self.user
        with patch('app.views._user_kite', return_value=object()):
            response = quote(request)

        self.assertEqual(json.loads(response.content), {'ok': False})


class AdditionalHelperCoverageTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username='helper-owner', password='helper-pass')
        self.admin_user = User.objects.create_user(username='helper-admin', password='helper-pass')
        self.admin_user.profile.role = Profile.ADMIN_ONLY
        self.admin_user.profile.save()
        self.other = User.objects.create_user(username='helper-other', password='helper-pass')
        self.owner_account = KiteUser.objects.create(owner=self.owner, api_key='helper-api', access_token='tok', user_name='Owner User')
        self.other_account = KiteUser.objects.create(owner=self.other, api_key='helper-other-api', access_token='tok2', user_name='Other User')

    @patch('app.views._auth_status', return_value='active')
    def test_user_rows_filters_by_owner_and_owner_filter(self, _mock_status):
        own_rows = _user_rows(self.owner)
        admin_rows = _user_rows(self.admin_user, owner_filter='helper-other')

        self.assertEqual([row['user'].api_key for row in own_rows], ['helper-api'])
        self.assertEqual([row['user'].api_key for row in admin_rows], ['helper-other-api'])

    @patch('app.views._call_with_token_renewal', return_value='raw-profile')
    def test_sync_profile_returns_non_dict_without_persisting(self, _mock_call):
        self.owner_account.user_name = 'Before'
        self.owner_account.save(update_fields=['user_name'])

        result = _sync_profile_from_kite(self.owner_account)
        self.owner_account.refresh_from_db()

        self.assertEqual(result, 'raw-profile')
        self.assertEqual(self.owner_account.user_name, 'Before')

    def test_trade_data_handles_list_positions_and_utilized_fallback(self):
        class _KiteListStub:
            def profile(self):
                return []

            def orders(self):
                return 'not-a-list'

            def margins(self):
                return {'equity': {'available': {'cash': '500'}, 'utilized': {'debits': '12.5'}, 'net': '1000'}}

            def holdings(self):
                return 'bad-holdings'

            def positions(self):
                return [{'tradingsymbol': 'SBIN', 'quantity': '2', 'average_price': '100.5', 'pnl': '3.5'}]

        with patch('app.views._call_with_token_renewal', side_effect=lambda _user, operation: operation(_KiteListStub())):
            data = _trade_data_for_user(self.owner_account)

        self.assertIsNone(data['profile'])
        self.assertEqual(data['orders'] if 'orders' in data else [], [])
        self.assertEqual(data['cash'], 500)
        self.assertEqual(data['debits'], 12.5)
        self.assertEqual(len(data['positions']), 1)
        self.assertEqual(data['positions'][0]['average_price'], 100.5)

    def test_owner_choices_returns_only_users_with_accounts(self):
        no_account_user = User.objects.create_user(username='no-account', password='pass')

        usernames = [user.username for user in _owner_choices()]

        self.assertIn('helper-owner', usernames)
        self.assertIn('helper-other', usernames)
        self.assertNotIn(no_account_user.username, usernames)

    def test_helper_fallbacks_cover_none_and_passthrough_cases(self):
        self.assertIsNone(_scalar_value([]))
        self.assertIsNone(_sum_numeric_values([]))
        self.assertIsNone(_calculate_margin_used({'other': {'foo': 'bar'}}))
        self.assertEqual(_normalize_position('raw-position'), 'raw-position')

    def test_trade_data_handles_non_dict_positions_payload_and_plain_margin_dict(self):
        class _KiteWeirdStub:
            def profile(self):
                return {'user_name': 'Helper'}

            def orders(self):
                return []

            def margins(self):
                return {'net': '200', 'available': {'cash': '25'}}

            def holdings(self):
                return []

            def positions(self):
                return 'unexpected'

        with patch('app.views._call_with_token_renewal', side_effect=lambda _user, operation: operation(_KiteWeirdStub())):
            data = _trade_data_for_user(self.owner_account)

        self.assertEqual(data['positions'], [])
        self.assertEqual(data['net'], 200)
        self.assertEqual(data['cash'], 25)

    def test_trade_data_includes_order_price_quantity_and_status_message_fields(self):
        class _KiteOrderStub:
            def profile(self):
                return {'user_name': 'Helper'}

            def orders(self):
                return [{
                    'order_id': 'ORD123',
                    'status': 'OPEN',
                    'status_message': 'Order is pending at exchange',
                    'price': '101.5',
                    'trigger_price': '100',
                    'average_price': '99.8',
                    'quantity': '10',
                    'filled_quantity': '3',
                    'pending_quantity': '7',
                }]

            def margins(self):
                return {'equity': {'available': {}, 'utilized': {}, 'net': '0'}}

            def holdings(self):
                return []

            def positions(self):
                return []

        with patch('app.views._call_with_token_renewal', side_effect=lambda _user, operation: operation(_KiteOrderStub())):
            data = _trade_data_for_user(self.owner_account)

        self.assertEqual(len(data['open_orders']), 1)
        self.assertEqual(data['open_orders'][0]['price'], 101.5)
        self.assertEqual(data['open_orders'][0]['trigger_price'], 100)
        self.assertEqual(data['open_orders'][0]['average_price'], 99.8)
        self.assertEqual(data['open_orders'][0]['quantity'], 10)
        self.assertEqual(data['open_orders'][0]['filled_quantity'], 3)
        self.assertEqual(data['open_orders'][0]['pending_quantity'], 7)
        self.assertEqual(data['order_status_messages'][0]['status'], 'OPEN')
        self.assertEqual(data['order_status_messages'][0]['status_message'], 'Order is pending at exchange')


class AdditionalTokenStatusAndTradeTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.admin_user = User.objects.create_user(username='status-admin', password='pass')
        self.admin_user.profile.role = Profile.ADMIN_ONLY
        self.admin_user.profile.save()
        self.owner = User.objects.create_user(username='status-owner', password='pass')
        self.other = User.objects.create_user(username='status-other', password='pass')
        self.owner_account = KiteUser.objects.create(owner=self.owner, api_key='status-api', access_token='tok')
        self.other_account = KiteUser.objects.create(owner=self.other, api_key='other-status-api', access_token='tok2')

    @patch('app.views._auth_status', return_value='active')
    def test_token_statuses_admin_owner_filter_limits_payload(self, _mock_status):
        request = self.factory.get(reverse('token_statuses'), {'owner': 'status-other'})
        request.user = self.admin_user

        response = token_statuses(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertIn(self.other_account.zk_user_id, payload['statuses_by_id'])
        self.assertNotIn(self.owner_account.zk_user_id, payload['statuses_by_id'])

    @patch('app.views._auth_status', return_value='active')
    @patch('app.views._trade_data_for_user', side_effect=KiteException('trade down'))
    def test_trade_refresh_returns_empty_payload_on_trade_error(self, _mock_trade_data, _mock_status):
        request = self.factory.get(reverse('trade_refresh_data'), {'api_key': 'status-api'})
        request.user = self.owner

        response = trade_refresh_data(request)
        payload = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['open_orders'], [])
        self.assertEqual(payload['api_key'], 'status-api')

    def test_trade_refresh_selected_user_not_authorized_for_all_mode(self):
        request = self.factory.get(reverse('trade_refresh_data'), {'api_key': 'all', 'selected_api_key': 'other-status-api'})
        request.user = self.owner

        response = trade_refresh_data(request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content)['error'], 'Not authorized to refresh all accounts.')


class AdditionalOrderFailureTests(TestCase):
    class _NoQuoteKite:
        def quote(self, key):
            raise KiteException('quote down')

        def place_order(self, **kwargs):
            return 'ORDER'

    def test_place_raises_for_non_positive_quantity(self):
        with self.assertRaises(ValueError):
            _place(self._NoQuoteKite(), {
                'exchange': 'NSE',
                'tradingsymbol': 'INFY',
                'transaction_type': 'BUY',
                'quantity': '0',
                'product': 'CNC',
                'order_type': 'MARKET',
            })

    def test_place_allows_limit_when_quote_lookup_fails(self):
        order_id = _place(self._NoQuoteKite(), {
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '1',
            'product': 'CNC',
            'order_type': 'LIMIT',
            'price': '100',
        })

        self.assertEqual(order_id, 'ORDER')


class AdditionalCacheAndEndpointTests(TestCase):
    def test_get_instruments_uses_cache_on_second_call(self):
        class _KiteStub:
            def __init__(self):
                self.calls = 0

            def instruments(self, exchange):
                self.calls += 1
                return [{'tradingsymbol': 'INFY'}]

        kite = _KiteStub()
        _INSTRUMENTS_CACHE.clear()

        first = _get_instruments(kite, 'NSE')
        second = _get_instruments(kite, 'NSE')

        self.assertEqual(first, second)
        self.assertEqual(kite.calls, 1)

    @patch('app.views._make_kite', return_value='kite-client')
    @patch('app.views._call_with_token_renewal', return_value={'user_name': 'ok'})
    def test_user_kite_without_request_user_skips_owner_filter(self, _mock_call, _mock_make_kite):
        user = User.objects.create_user(username='cache-user', password='pass')
        kite_user = KiteUser.objects.create(owner=user, api_key='cache-api', access_token='cache-token')

        result = _user_kite(kite_user.api_key)

        self.assertEqual(result, 'kite-client')

    def tearDown(self):
        _INSTRUMENTS_CACHE.clear()


class LoginAndTradeIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        settings.SECRET_KEY = 'test-secret-key'

    def setUp(self):
        self.user = User.objects.create_user(username='flow-user', password='flow-pass-123')
        self.other = User.objects.create_user(username='flow-other', password='flow-other-pass')
        self.kite_user = KiteUser.objects.create(
            owner=self.user,
            api_key='flow-api',
            access_token='flow-token',
            user_name='Flow User',
            user_id='FL1234',
            email='flow@example.com',
        )
        self.other_kite_user = KiteUser.objects.create(
            owner=self.other,
            api_key='other-flow-api',
            access_token='other-flow-token',
            user_name='Other User',
            user_id='OT5678',
        )

    @override_settings(SECURE_SSL_REDIRECT=False, LOGIN_RATE_LIMIT_ATTEMPTS=5)
    def test_login_post_redirects_to_home(self):
        response = self.client.post(reverse('login'), {
            'username': 'flow-user',
            'password': 'flow-pass-123',
            'next': '/',
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/')

        home_response = self.client.get(reverse('home'))
        self.assertEqual(home_response.status_code, 200)
        self.assertContains(home_response, 'Home Page')

    @override_settings(SECURE_SSL_REDIRECT=False)
    @patch('app.views._auth_status', return_value='active')
    @patch('app.views._trade_data_for_user')
    def test_trade_page_renders_selected_owned_account(self, mock_trade_data, _mock_status):
        self.client.force_login(self.user)
        mock_trade_data.return_value = {
            'profile': {'user_name': 'Flow User', 'email': 'flow@example.com'},
            'open_orders': [{'order_id': 'OID1', 'tradingsymbol': 'INFY', 'transaction_type': 'BUY', 'quantity': 1, 'order_timestamp': '2026-07-03 10:00:00', 'exchange': 'NSE', 'price': 100, 'product': 'CNC', 'order_type': 'LIMIT'}],
            'executed_orders': [],
            'cancelled_orders': [],
            'holdings': [],
            'positions': [],
            'holdings_pnl': 0,
            'positions_pnl': 0,
            'net': 1000,
            'opening_balance': 900,
            'live_balance': 950,
            'cash': 800,
            'debits': 50,
        }

        response = self.client.get(reverse('trade'), {'api_key': 'flow-api'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Flow User')
        self.assertContains(response, 'Open orders (1)')
        self.assertContains(response, 'OID1')
        self.assertContains(response, 'Active')

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_trade_page_blocks_access_to_other_users_account(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse('trade'), {'api_key': 'other-flow-api'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Not authorized for this account.')

    @override_settings(SECURE_SSL_REDIRECT=False)
    @patch('app.views._user_kite')
    def test_trade_place_redirects_with_success_banner(self, mock_user_kite):
        class _KitePlaceStub:
            def place_order(self, **kwargs):
                return 'ORDER-123'

            def quote(self, key):
                return {key: {'circuit_limit': {'lower': 90, 'upper': 110}}}

        self.client.force_login(self.user)
        mock_user_kite.return_value = _KitePlaceStub()

        response = self.client.post(reverse('trade_place'), {
            'api_key': 'flow-api',
            'exchange': 'NSE',
            'tradingsymbol': 'INFY',
            'transaction_type': 'BUY',
            'quantity': '1',
            'product': 'CNC',
            'order_type': 'LIMIT',
            'price': '100',
        })

        self.assertEqual(response.status_code, 302)
        self.assertIn('msg=Order+placed+%28ID+ORDER-123%29.', response['Location'])
