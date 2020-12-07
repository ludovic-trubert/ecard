#!/usr/bin/python3

import json
import unittest.mock
from unittest import mock
from unittest.mock import patch, DEFAULT

import ecard
from ecard import ECardManager


def mocked_requests_response(*args, **kwargs):
    class MockResponse:
        def __init__(self, _status_code, _headers, _cookies, _text):
            self.status_code = _status_code
            self.headers = _headers
            self.cookies = _cookies
            self.text = _text

    file = args[0]
    with open('./mocks/' + file + '.json') as json_file:
        data = json.load(json_file)

        status_code = data['response']['status']

        body = None
        if 'text' in data['response']['content']:
            body = data['response']['content']['text']

        headers = {}
        cookies = {}
        for header in data['response']['headers']:
            key = header['name']
            value = header['value']
            if headers.__contains__(key):
                value = headers[key] + ';' + value
            headers[key] = value
        for cookie in data['response']['cookies']:
            cookies[cookie['name']] = cookie['value']

    return MockResponse(status_code, headers, cookies, body)


class ECardTest(unittest.TestCase):
    bank_host = 'https://service.e-cartebleue.com/fr/caisse-epargne'
    t3ds_host = 'https://natixispaymentsolutions-3ds-vdm.wlp-acs.com'

    @patch('requests.post', side_effect=[mocked_requests_response('login_success')])
    def test_do_login_success(self, mock_post):

        # Given
        e_card_manager = ECardManager()

        # When
        succeed = e_card_manager.do_login('login', 'password')

        # Then
        self.assertEqual(succeed, True)
        self.assertEqual('1234567890ABCDEF1234567890ABCDEF', e_card_manager.jsessionid)
        self.assertEqual('9876543210', e_card_manager.token)
        self.assertEqual(False, e_card_manager.auth_3ds_needed)

        # assert mocked being called with the right parameters
        expected_url = 'https://service.e-cartebleue.com/fr/caisse-epargne/login'
        expected_data = 'request=login&identifiantCrypte=&app=&identifiant=login&memorize=false&password=password&token=9876543210'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, data=expected_data, headers=expected_headers),
                         mock_post.call_args_list[0])

    @patch('requests.post', side_effect=[mocked_requests_response('login_failed')])
    def test_do_login_failed(self, mock_post):

        # Given
        e_card_manager = ECardManager()

        # When
        try:
            e_card_manager.do_login('login', 'password')

        # Then
        except Exception as e:
            self.assertEqual('Votre identification est incorrecte.', str(e))

        self.assertEqual(None, e_card_manager.jsessionid)
        self.assertEqual(None, e_card_manager.token)
        self.assertEqual(None, e_card_manager.auth_3ds_needed)

        # assert mocked being called with the right parameters
        expected_url = 'https://service.e-cartebleue.com/fr/caisse-epargne/login'
        expected_data = 'request=login&identifiantCrypte=&app=&identifiant=login&memorize=false&password=password&token=9876543210'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, data=expected_data, headers=expected_headers),
                         mock_post.call_args_list[0])

    @patch('requests.post', side_effect=[mocked_requests_response('login_blocked')])
    def test_do_login_blocked(self, mock_post):

        # Given
        e_card_manager = ECardManager()

        # When
        try:
            e_card_manager.do_login('login', 'password')

        # Then
        except Exception as e:
            self.assertEqual("Vous venez d'effectuer trop d'identifications incorrectes.\n"
                             "Pour des raisons de sécurité, le système est maintenant bloqué.\n"
                             "Veuillez contacter votre banque.", str(e))

        self.assertEqual(None, e_card_manager.jsessionid)
        self.assertEqual(None, e_card_manager.token)
        self.assertEqual(None, e_card_manager.auth_3ds_needed)

        # assert mocked being called with the right parameters
        expected_url = self.bank_host + '/login'
        expected_data = 'request=login&identifiantCrypte=&app=&identifiant=login&memorize=false&password=password&token=9876543210'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, data=expected_data, headers=expected_headers),
                         mock_post.call_args_list[0])

    @patch('requests.get', side_effect=[mocked_requests_response('logout')])
    def test_do_logout(self, mock_get):

        # Given
        e_card_manager = ECardManager()
        e_card_manager.jsessionid = '1234567890ABCDEF1234567890ABCDEF'
        e_card_manager.token = '9876543210'
        e_card_manager.need3dsecure = False

        # When
        e_card_manager.do_logout()

        # Then
        # assert mocked being called with the right parameters
        expected_url = self.bank_host + '/logout'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Cookie': 'JSESSIONID=1234567890ABCDEF1234567890ABCDEF; eCarteBleue-pref=open'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, headers=expected_headers),
                         mock_get.call_args_list[0])

    @patch('requests.post', side_effect=[mocked_requests_response('generate_ecard_success')])
    def test_generate_ecard_success(self, mock_post):

        # Given
        e_card_manager = ECardManager()
        e_card_manager.jsessionid = '1234567890ABCDEF1234567890ABCDEF'
        e_card_manager.token = '9876543210'
        e_card_manager.auth_3ds_needed = False

        # When
        e_card = e_card_manager.generate_ecard('10.54', '1.000000', '3')

        # Then
        self.assertEqual('1234567890123456', e_card.number)
        self.assertEqual('01/23', e_card.expired_at)
        self.assertEqual('123', e_card.cvv)
        self.assertEqual('M XXXXX YYYYY', e_card.owner)

        # assert mocked being called with the right parameters
        expected_url = self.bank_host + '/cpn'
        expected_data = 'request=ocode&token=9876543210&montant=10.54&devise=1.000000&dateValidite=3'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': 'JSESSIONID=1234567890ABCDEF1234567890ABCDEF; eCarteBleue-pref=open'
        }

        self.assertEqual(mock.call(expected_url, allow_redirects=True, data=expected_data, headers=expected_headers),
                         mock_post.call_args_list[0])

    @patch('requests.post', side_effect=[mocked_requests_response('login_success_auth_3ds_needed')])
    def test_do_login_success_auth_3ds_needed(self, mock_post):

        # Given
        e_card_manager = ECardManager()

        # When
        succeed = e_card_manager.do_login('login', 'password')

        # Then
        self.assertEqual(succeed, True)
        self.assertEqual('1234567890ABCDEF1234567890ABCDEF', e_card_manager.jsessionid)
        self.assertEqual('9876543210', e_card_manager.token)
        self.assertEqual(True, e_card_manager.auth_3ds_needed)
        self.assertEqual('MD123456789012345678', e_card_manager.auth_3ds_md)
        self.assertEqual('PaReqABCDEF1234567890ABCDEF1234567890', e_card_manager.auth_3ds_pareq)
        self.assertEqual('/fr/caisse-epargne/receive3ds', e_card_manager.auth_3ds_termurl)

        # assert mocked being called with the right parameters
        expected_url = self.bank_host + '/login'
        expected_data = 'request=login&identifiantCrypte=&app=&identifiant=login&memorize=false&password=password&token=9876543210'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, data=expected_data, headers=expected_headers),
                         mock_post.call_args_list[0])

    @patch('builtins.input', return_value='12345678')
    @patch.multiple('requests', post=DEFAULT, get=DEFAULT)
    def test_auth_3ds(self, mock_input, **mocks):

        # Given
        mocks['get'].side_effect = [mocked_requests_response('auth_3ds_1_parequest_redirect')]
        mocks['post'].side_effect = [mocked_requests_response('auth_3ds_1_parequest'),
                                     mocked_requests_response('auth_3ds_2_getsession'),
                                     mocked_requests_response('auth_3ds_3_startauthent'),
                                     mocked_requests_response('auth_3ds_4_updateauthent'),
                                     mocked_requests_response('auth_3ds_5_endauthent'),
                                     mocked_requests_response('auth_3ds_6_parequestfromauthpages'),
                                     mocked_requests_response('receive3ds')]

        e_card_manager = ECardManager()
        e_card_manager.jsessionid = '1234567890ABCDEF1234567890ABCDEF'
        e_card_manager.token = '9876543210'
        e_card_manager.auth_3ds_needed = True
        e_card_manager.auth_3ds_url = self.t3ds_host + '/acs-pa-service/pa/paRequest'
        e_card_manager.auth_3ds_md = 'MD123456789012345678'
        e_card_manager.auth_3ds_pareq = 'PaReqABCDEF1234567890ABCDEF1234567890'
        e_card_manager.auth_3ds_termurl = '/fr/caisse-epargne/receive3ds'

        # When
        e_card_manager.auth_3ds()

        # Then
        # 1.1 check PaRequest
        expected_url = self.t3ds_host + '/acs-pa-service/pa/paRequest'
        expected_data = 'MD=MD123456789012345678' \
                        '&PaReq=PaReqABCDEF1234567890ABCDEF1234567890' \
                        '&TermUrl=https%3A%2F%2Fservice.e-cartebleue.com%2Ffr%2Fcaisse-epargne%2Freceive3ds'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=False, data=expected_data, headers=expected_headers),
                         mocks['post'].call_args_list[0])

        # 1.2 check PaRequest redirection
        expected_url = self.t3ds_host + '/acs-auth-pages/authent/pages/3ds1234567890abcdef1234567890abcdef'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, headers=expected_headers),
                         mocks['get'].call_args_list[0])

        # 2. check getSession
        expected_url = self.t3ds_host + '/acs-auth-pages/authent/pages/getSession' \
                                        '/3ds1234567890abcdef1234567890abcdef'
        expected_data = '{"inIframe": false, "parentUrl": null}'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/json'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, headers=expected_headers, data=expected_data),
                         mocks['post'].call_args_list[1])

        # 3. check startAuthent
        expected_url = self.t3ds_host + '/acs-auth-pages/authent/pages/startAuthent'
        expected_data = '{"accountId": "accid1234567890-1234567890", "language": "fr", "region": "FR", "hubAuthenticationInput": {"transactionContext": {}}}'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/json'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, headers=expected_headers, data=expected_data),
                         mocks['post'].call_args_list[2])

        # 4. check updateAuthent
        expected_url = self.t3ds_host + '/acs-auth-pages/authent/pages/updateAuthent'
        expected_data = '{"accountId": "accid1234567890-1234567890", "language": "fr", "step": "otp_validating_3", ' \
                        '"skipCurrentHubCall": false, "hubAuthenticationInput": {"otp": "12345678", "merchantWhitelistedByUser": false}}'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/json'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, headers=expected_headers, data=expected_data),
                         mocks['post'].call_args_list[3])

        # 5. check endAuthent
        expected_url = self.t3ds_host + '/acs-auth-pages/authent/pages/endAuthent'
        expected_data = '{"accountId": "accid1234567890-1234567890", "hubAuthenticationInput": {}}'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/json'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, headers=expected_headers, data=expected_data),
                         mocks['post'].call_args_list[4])

        # 6. check paRequestFromAuthPages
        expected_url = self.t3ds_host + '/acs-pa-service/pa/paRequestFromAuthPages'
        expected_data = 'accountId=accid1234567890-1234567890'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Upgrade-Insecure-Requests': '1'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, headers=expected_headers, data=expected_data),
                         mocks['post'].call_args_list[5])

        # finally, check received3ds
        expected_url = self.bank_host + '/receive3ds'
        expected_data = 'MD=MDRESP1234567890&PaRes=PARES12345678901234567890'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': 'JSESSIONID=1234567890ABCDEF1234567890ABCDEF; eCarteBleue-pref=open',
            'Upgrade-Insecure-Requests': '1'
        }
        self.assertEqual(mock.call(expected_url, allow_redirects=True, headers=expected_headers, data=expected_data),
                         mocks['post'].call_args_list[6])

    if __name__ == '__main__':
        unittest.main()
