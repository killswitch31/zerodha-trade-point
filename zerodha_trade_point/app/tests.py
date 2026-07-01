"""Tests for Configure ZK Auth behavior and token status payloads."""

import json
from unittest.mock import patch
from django.contrib.auth.models import User
from django.test import TestCase, RequestFactory
from django.urls import reverse
from kiteconnect.exceptions import KiteException
from app.forms import AddUserForm
from app.models import KiteUser
from app.views import token_statuses, configurezkauth, _kite_login_url, trade, _place, trade_modify, _trade_data_for_user


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
