#!/usr/bin/python3

import json
import logging
import unittest.mock
from unittest import mock
from unittest.mock import patch

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

    yield MockResponse(status_code, headers, cookies, body)


class ECardTest(unittest.TestCase):

    @patch('requests.post', side_effect=mocked_requests_response('login_success'))
    def test_do_login_success(self, mock_post):

        # Given
        e_card_manager = ECardManager(logging.getLogger('ecard'))

        # When
        succeed = e_card_manager.do_login('login', 'password')

        # Then
        self.assertEqual(succeed, True)
        self.assertEqual('1234567890ABCDEF1234567890ABCDEF', e_card_manager.jsessionid)
        self.assertEqual('9876543210', e_card_manager.token)
        self.assertEqual(False, e_card_manager.need3dsecure)

        # assert mocked being called with the right parameters
        expected_url = 'https://service.e-cartebleue.com/fr/caisse-epargne/login'
        expected_data = 'request=login&identifiantCrypte=&app=&identifiant=login&memorize=false&password=password&token=9876543210';
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.assertIn(mock.call(expected_url, data=expected_data, headers=expected_headers), mock_post.call_args_list)

    @patch('requests.post', side_effect=mocked_requests_response('login_failed'))
    def test_do_login_failed(self, mock_post):

        # Given
        e_card_manager = ECardManager(logging.getLogger('ecard'))

        # When
        try:
            e_card_manager.do_login('login', 'password')

        # Then
        except Exception as e:
            self.assertEqual('Votre identification est incorrecte.', str(e))

        self.assertEqual(None, e_card_manager.jsessionid)
        self.assertEqual(None, e_card_manager.token)
        self.assertEqual(None, e_card_manager.need3dsecure)

        # assert mocked being called with the right parameters
        expected_url = 'https://service.e-cartebleue.com/fr/caisse-epargne/login'
        expected_data = 'request=login&identifiantCrypte=&app=&identifiant=login&memorize=false&password=password&token=9876543210';
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.assertIn(mock.call(expected_url, data=expected_data, headers=expected_headers), mock_post.call_args_list)

    @patch('requests.post', side_effect=mocked_requests_response('login_blocked'))
    def test_do_login_blocked(self, mock_post):

        # Given
        e_card_manager = ECardManager(logging.getLogger('ecard'))

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
        self.assertEqual(None, e_card_manager.need3dsecure)

        # assert mocked being called with the right parameters
        expected_url = 'https://service.e-cartebleue.com/fr/caisse-epargne/login'
        expected_data = 'request=login&identifiantCrypte=&app=&identifiant=login&memorize=false&password=password&token=9876543210';
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.assertIn(mock.call(expected_url, data=expected_data, headers=expected_headers), mock_post.call_args_list)

    @patch('requests.get', side_effect=mocked_requests_response('logout'))
    def test_do_logout(self, mock_get):

        # Given
        e_card_manager = ECardManager(logging.getLogger('ecard'))

        # When
        succeed = e_card_manager.do_logout()

        # Then
        # assert mocked being called with the right parameters
        expected_url = 'https://service.e-cartebleue.com/fr/caisse-epargne/logout'
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.assertIn(mock.call(expected_url, headers=expected_headers), mock_get.call_args_list)

    @patch('requests.post', side_effect=mocked_requests_response('generate_ecard_success'))
    def test_generate_ecard_success(self, mock_post):

        # Given
        e_card_manager = ECardManager(logging.getLogger('ecard'))
        e_card_manager.jsessionid = '1234567890ABCDEF1234567890ABCDEF'
        e_card_manager.token = '9876543210'
        e_card_manager.need3dsecure = False

        # When
        e_card = e_card_manager.generate_ecard('10.54', '1.000000', '3')

        # Then
        self.assertEqual('1234567890123456', e_card.number)
        self.assertEqual('01/23', e_card.expired_at)
        self.assertEqual('123', e_card.cvv)
        self.assertEqual('M XXXXX YYYYY', e_card.owner)

        # assert mocked being called with the right parameters
        expected_url = 'https://service.e-cartebleue.com/fr/caisse-epargne/cpn'
        expected_data = 'request=ocode&token=9876543210&montant=10.54&devise=1.000000&dateValidite=3';
        expected_headers = {
            'User-Agent': 'ecartebleue-python/' + ecard.__version__, 'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': 'JSESSIONID=1234567890ABCDEF1234567890ABCDEF; eCarteBleue-pref=open'
        }

        self.assertIn(mock.call(expected_url, data=expected_data, headers=expected_headers), mock_post.call_args_list)

    if __name__ == '__main__':
        unittest.main()
