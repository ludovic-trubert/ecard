#!/usr/bin/python3

import argparse
import logging
import subprocess
import sys
import urllib.parse
import urllib.request

import lxml.html as html_parser
import requests

__version__ = 'latest'

# ----- CONFIGURATION -----
# Bank's name is defined in the url of the e-cartebleue service.
# It could be caisse-epargne, sg, labanquepostale, banquepopulaire, banquebcp...
bank = 'caisse-epargne'

# gopass keys
login_gopass_location = 'me/sites/e-cartebleue.com/{card} user'
password_gopass_location = 'me/sites/e-cartebleue.com/{card}'
default_card = 'joint'


class ECard:
    def __init__(self, number, expired_at, cvv, owner):
        self.number = number
        self.expired_at = expired_at
        self.cvv = cvv
        self.owner = owner

    def __str__(self):
        return 'Card number : ' + str(self.number) \
               + '\nExpired at  : ' + str(self.expired_at) \
               + '\nCVV         : ' + str(self.cvv) \
               + '\nOwner       : ' + str(self.owner)


class ECardManager:
    def __init__(self):
        self.host = 'https://service.e-cartebleue.com/fr/' + bank
        self.token = None
        self.jsessionid = None
        self.need3dsecure = None

    def do_login(self, login, password):
        logger.debug('HEADER login')

        headers = ECardManager.get_common_headers({})
        payload = urllib.parse.urlencode({
            'request': 'login',
            'identifiantCrypte': '',
            'app': '',
            'identifiant': login,
            'memorize': 'false',
            'password': password,
            'token': '9876543210'
        })
        response = requests.post(self.host + '/login', headers=headers, data=payload)
        if response.status_code != 200:
            raise Exception('\n\033[91m/!\\ TECHNICAL ERROR /!\\\033[0m\nSomething went wrong during login. '
                            'The e-cartebleue service may not be available:\n\n' + response.text)
        html = response.text

        logger.debug('# headers\n' + str(response.headers))
        logger.debug('\n# body\n' + html.strip())

        dom = html_parser.document_fromstring(html)
        ECardManager.check_error(dom)

        logger.debug('\n# LoginInfo')

        # get jsessionid
        self.jsessionid = response.cookies['JSESSIONID']
        logger.debug('jsessionid: ' + self.jsessionid)

        # get token
        self.token = dom.xpath('//input[@name="token"]')[0].attrib['value'].strip()
        logger.debug('token: ' + self.token)

        # check if D secure is needed
        self.need3dsecure = len(dom.xpath('//form[@id="form-3ds-authentificate"]')) > 0
        logger.debug('need3dsecure: ' + str(self.need3dsecure))
        return True

    def generate_ecard(self, amount: str, currency: str, validity: str) -> ECard:
        logger.debug('HEADER generate ecard')

        headers = ECardManager.get_common_headers({
            'Cookie': 'JSESSIONID=' + self.jsessionid + '; eCarteBleue-pref=open'
        })
        payload = urllib.parse.urlencode({
            'request': 'ocode',
            'token': self.token,
            'montant': amount,
            'devise': currency,
            'dateValidite': validity
        })

        response = requests.post(self.host + '/cpn', headers=headers, data=payload)
        html = response.text

        logger.debug('# headers\n' + str(response.headers))
        logger.debug('\n# body\n' + html.strip())

        dom = html_parser.document_fromstring(html)
        ECardManager.check_error(dom)

        number = dom.xpath('//dd[@id="generated-code-dd"]/span[@data-drag-txt]')[0].attrib['data-drag-txt'].strip()
        expired_at = dom.xpath('//dl[@id="content-expiration-date"]/dd')[0].text.strip()
        cvv = dom.xpath('//dl[@id="content-cryptogramme"]//span[@class="restricted-only"]')[0].text.strip()
        owner = dom.xpath('//dl[@id="content-card-owner"]//span[@class="restricted-only"]')[0].text.strip()

        e_card = ECard(number, expired_at, cvv, owner)
        return e_card

    def do_logout(self):
        logger.debug('HEADER logout')
        headers = ECardManager.get_common_headers({})
        response = requests.get(self.host + '/logout', headers=headers)
        logger.debug('response: ' + str(response))
        if response.status_code != 200:
            raise Exception('\n\033[91m/!\\ TECHNICAL ERROR /!\\\033[0m\nSomething went wrong during logout. '
                            'The e-cartebleue service may not be available:\n\n' + str(response))

    @staticmethod
    def get_common_headers(extra_headers: dict) -> dict:
        headers = {
            'User-Agent': 'ecartebleue-python/' + __version__,
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        headers.update(extra_headers)
        return headers

    @staticmethod
    def check_error(dom: html_parser) -> None:
        errors = dom.xpath('//form[@id="form-error-confirmation"]//p[@role="alert"]')
        if len(errors) > 0:
            # convert <br> to \n
            for br in errors[0].xpath('//br'):
                br.tail = '\n' + br.tail if br.tail else '\n'
            raise Exception(errors[0].text_content().strip())


class ColourFilter(logging.Filter):
    colours = {'DEBUG': '\033[32m',
               'INFO': '\033[34m',
               'WARNING': '\033[93m',
               'ERROR': '\033[91m',
               'CRITICAL': '\033[4m\033[1m\033[91m'}

    def filter(self, record):
        msg = record.msg.replace('HEADER', '\n########################## ')
        record.msg = ColourFilter.colours[record.levelname] + msg + '\033[0m'
        return True


class ChoicesFormatter(argparse.RawTextHelpFormatter):
    def _format_action_invocation(self, action):
        return super(ChoicesFormatter, self)._format_action_invocation(action).replace(' ,', ',')


# run bash command
def bash(bash_command):
    try:
        process = subprocess.run(bash_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        error = process.stderr.decode('utf-8').strip()
        if error:
            sys.stderr.write(error)
            sys.exit(1)
        return process.stdout.decode('utf-8').strip().split('\n', 1)[0]
    except subprocess.CalledProcessError:
        print("error run command: " + bash_command)
        sys.exit(1)


def amount_type(x):
    if float(x) <= 0.0:
        raise argparse.ArgumentTypeError("amount must be greater than 0")
    return x


def action_generate(args, e_card_manager: ECardManager):
    # params
    logger.debug('expire-in: ' + args.expire_in)
    logger.debug('amount: ' + args.amount)

    e_card = e_card_manager.generate_ecard(args.amount, '1.000000', args.expire_in)
    print(e_card)


def run(args, action):
    # gopass
    login = bash('gopass ' + login_gopass_location.format(card=args.card))
    logger.debug('login: ' + login)

    password = bash('gopass ' + password_gopass_location.format(card=args.card))
    logger.debug('password: ')

    e_card_manager = ECardManager()
    try:
        # login
        e_card_manager.do_login(login, password)
        if e_card_manager.need3dsecure:
            print('3D secure auth required - not supported - please login to the website to continue')
        else:
            action(args, e_card_manager)
    except Exception as e:
        print(e)
    finally:
        e_card_manager.do_logout()
        sys.exit(1)


# logger
logging.basicConfig(format='%(message)s')
logger = logging.getLogger('ecard')
logger.addFilter(ColourFilter())

# MAIN
if __name__ == '__main__':
    # arguments
    expire_in = ['3', '6', '9', '12', '15', '18', '21', '24']
    parser = argparse.ArgumentParser(formatter_class=ChoicesFormatter)
    parser.add_argument('amount', type=amount_type, help='amount in euro')
    parser.add_argument('-c', '--card', default=default_card, help='card''s name defined in gopass')
    parser.add_argument('-e', '--expire-in', choices=expire_in, default='3', metavar='',
                        help='expiration time in months, default is 3\nallowed values are ' + ', '.join(
                            expire_in) + '.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='verbose mode')
    parser.add_argument('-V', '--version', action='version', version=__version__, help='display version and quit')
    _args = parser.parse_args()

    # set logger level
    level = logging.DEBUG if _args.verbose else logging.INFO
    logger.setLevel(level)

    # action
    run(_args, action_generate)
