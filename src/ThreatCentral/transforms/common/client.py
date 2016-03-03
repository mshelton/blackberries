#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) Copyright [2016] Hewlett Packard Enterprise Development LP Licensed under
# the Apache License, Version 2.0 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of the License
# at  Unless required by applicable
# law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

from threatcentral import ThreatCentral, ThreatCentralError
from os import makedirs
from os.path import isfile, sep, abspath, dirname, expanduser, isdir, join
from ConfigParser import SafeConfigParser, NoOptionError, NoSectionError
from shutil import copyfile
from canari.maltego.message import UIMessage
from tldextract import extract
from urlparse import urlparse, parse_qs

import re

__author__ = 'Bart Otten'
__copyright__ = '(c) Copyright [2016] Hewlett Packard Enterprise Development LP'
__credits__ = []

__license__ = 'Apache 2.0'
__version__ = '1'
__maintainer__ = 'Bart Otten'
__email__ = 'tc-support@hpe.com'
__status__ = 'Development'

conf_filename = 'ThreatCentral.conf'
conf_path = join(expanduser("~"), '.canari', conf_filename)
conf_contents = dict(section='threatcentral',
                     values=dict(apikey='your_apikey'))

canari_conf_path = join(expanduser("~"), '.canari', 'canari.conf')

tc = ThreatCentral()

s_lower = str.lower
u_lower = unicode.lower

s_upper = str.upper
u_upper = unicode.upper


class PrintMaltego(object):

    def __init__(self, msg):
        self.msg = msg

    def __call__(self, *args):
        UIMessage(self.msg())


# Todo Change or remove this
def __config__(section, option):
    conf_file = None
    # Check if ~/.canari/<conf_file> exists
    if isfile(expanduser("~")+sep+'.canari'+sep+conf_filename):
        conf_file = expanduser("~")+sep+'.canari'+sep+conf_filename
    elif isfile(dirname(abspath(__file__)).rsplit(sep, 3)[0]+sep+conf_filename):
        conf_file = dirname(abspath(__file__)).rsplit(sep, 3)[0]+sep+conf_filename

    # Read 'section/option'
    '''
    if conf_file:
        config.read(filenames=conf_file)
        if section in config.sections():
            if config.has_option(section=section, option=option):
                return config.get(section=section, option=option)
    '''


# TODO Change/Remove this function
def check_config():
    # Check folder ~/.canari/
    if not isdir(expanduser("~")+sep+'.canari'):
        print "~/.canari does not exists, creating folder..."
        try:
            makedirs(expanduser("~")+sep+'.canari')
            print "~/.canari created!"
        except OSError:
            print "Error creating folder: ~/.canari"
    else:
        # Check ~/.canari/configfile.conf
        fn = join(expanduser("~"), '.canari', conf_filename)
        if not isfile(fn):
            print '{} does not exist, checking original file...'.format(fn)
            if isfile(conf_path):
                print "Original file found, copying {} to ~/.canari/".format(fn)
                try:
                    copyfile(conf_path, fn)
                    return True
                except IOError as e:
                    print "Error: {}".format(e)
            else:
                print "Original file not found! Creating new file..."
                cnf = SafeConfigParser()
                try:
                    cnf.add_section(conf_contents.get('section'))
                    for k, v in conf_contents.get('values', dict()).items():
                        print "{}:{}".format(k, v)
                        cnf.set(conf_contents.get('section'), k, v)
                except KeyError:
                    print "Error creating new file!!"

                try:
                    with open(fn, 'w') as f:
                        cnf.write(f)
                    print "{} created".format(fn)
                    return True
                except IOError as e:
                    print "Error: {}".format(e)
        return True


def get_from_config(option, section=None, path=conf_path):
    cnf = SafeConfigParser()
    try:
        cnf.readfp(open(path, 'r'))
        if not section:
            section = conf_contents.get('section')
        return cnf.get(section, option)
    except IOError:
        print "Error reading {}".format(path)
    except KeyError:
        print "Section: {} not found!".format(section)
    except NoSectionError:
        print "Section: {} not found!".format(section)
    except NoOptionError:
        print "Option: {} not found!".format(option)


def set_to_config(option, value, section=None, path=conf_path):
    cnf = SafeConfigParser()
    try:
        if not section:
            section = conf_contents.get('section')
        cnf.readfp(open(path, 'r'))
        if not cnf.has_section(section) and section.lower() != 'default':
            cnf.add_section(section)
        cnf.set(section, option, value)
        with open(path, 'w') as f:
            cnf.write(f)
        return True
    except IOError:
        print "Error reading/writing {}".format(path)
    except KeyError:
        print "Section: {} not found!".format(section)
    except ValueError as e:
        print e
    except NoSectionError:
        print "Section: {} not found!".format(section)
    except NoOptionError:
        print "Option: {} not found!".format(option)


def tc_auth():
    tc.auth = (get_from_config(option='apikey'), '')


def generate_apikey(username, password):
    tc.auth = (username, password)
    return tc.generate_api_key()


def search(value, size=100, pages=0):
    tc_auth()
    tc.cur_page['size'] = size
    return tc.search(value, pages=pages, exactmatch=True)


def search_indicator(value, size=100, pages=0):
    tc_auth()
    tc.cur_page['size'] = size
    return tc.search_indicator(value, pages=pages, exactmatch=True)


def search_incident(value, size=100, pages=0):
    tc_auth()
    tc.cur_page['size'] = size
    return tc.search_incident(value, pages=pages, exactmatch=True)


def search_actor(value, size=100, pages=0):
    tc_auth()
    tc.cur_page['size'] = size
    return tc.search_actor(value, pages=pages, exactmatch=True)


def search_case(value, size=100, pages=0):
    tc_auth()
    tc.cur_page['size'] = size
    return tc.search_case(value, pages=pages, exactmatch=True)


def search_ttp(value, size=100, pages=0):
    tc_auth()
    tc.cur_page['size'] = size
    return tc.search_ttp(value, pages=pages, exactmatch=True)


def get_actor(value):
    tc_auth()
    return tc.get_actor(value)


def get_case(value):
    tc_auth()
    return tc.get_case(value)


def get_indicator(value):
    tc_auth()
    return tc.get_indicator(value)


def get_incident(value):
    tc_auth()
    return tc.get_incident(value)


def get_ttp(value):
    tc_auth()
    return tc.get_ttp(value)


def get_linked_actors(value):
    tc_auth()
    return tc.get_linked_actors(value)


def get_linked_cases(value):
    tc_auth()
    return tc.get_linked_cases(value)


def get_linked_indicators(value):
    tc_auth()
    return tc.get_linked_indicators(value)


def get_linked_incidents(value):
    tc_auth()
    return tc.get_linked_incidents(value)


# Replace SOFT HYPHEN with normal dash
def encode_to_utf8(value):
    if value and type(value) == str or type(value) == unicode:
        if u'\xad' in value:
            value = value.replace(u'\xad', '-')
        try:
            return value.encode('ascii', 'ignore').encode('utf-8', errors='replace')
        except UnicodeEncodeError as e:
            return 'Error: {}'.format(e)
    elif value:
        return value
    else:
        return ''


def lower(value):
    if value:
        if type(value) == str:
            return s_lower(value)
        elif type(value) == unicode:
            return u_lower(value)
        else:
            return value
    return value


def upper(value):
    if value:
        if type(value) == str:
            return s_upper(value)
        elif type(value) == unicode:
            return u_upper(value)
        else:
            return value
    return value


# TODO OLD Functions Change this

def ipv4validator(ip):
    ipv4_regex = re.compile(r'^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$')
    if not ipv4_regex.match(ip):
        return False
    return True

"""
    This function is based on: https://github.com/marshmallow-code/marshmallow/blob/pypi/marshmallow/validate.py
    https://github.com/marshmallow-code/marshmallow/blob/pypi/LICENSE
"""


def emailvalidator(email):

    user_regex = re.compile(
        r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*$"  # dot-atom
        r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"$)',  # quoted-string
        re.IGNORECASE)
    domain_regex = re.compile(
        r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,})\.?$'  # domain
        # literal form, ipv4 address (SMTP 4.1.3)
        r'|^\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]$',
        re.IGNORECASE)

    domain_whitelist = ['localhost']

    if not email or '@' not in email:
        return False

    user_part, domain_part = email.rsplit('@', 1)

    if not user_regex.match(user_part):
        return False

    if domain_part not in domain_whitelist and not domain_regex.match(domain_part):
        try:
            domain_part = domain_part.encode('idna').decode('ascii')
            if not domain_regex.match(domain_part):
                return False
            else:
                return
        except UnicodeError:
            pass
        return False
    return True

"""
------------------------
"""


def search_domainnames_in_str(domain):
    # Valid
    domain_regex = re.compile(
        r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,})\.?$'  # domain
        # literal form, ipv4 address (SMTP 4.1.3)
        r'|^\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]$',
        re.IGNORECASE)
    domain_search = re.compile(r'[\w\-\.]+\.[a-zA-Z]{1,4}')  # domain

    found_domains = set()

    for d in domain_search.findall(domain):
        if domain_regex.match(d):
            found_domains.add(d)

    return found_domains


def search_emailaddress_in_str(data):
    results = set()
    mailaddress = re.compile(r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')
    findmailaddress = mailaddress.findall(data)
    for m in range(0, len(findmailaddress)):
        if emailvalidator(findmailaddress[m]):
            results.add(findmailaddress[m])

    return results


def search_ipv4address_in_str(data):
    results = set()
    ipaddress = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
    findipaddress = ipaddress.findall(data)
    for i in range(0, len(findipaddress)):
        if ipv4validator(findipaddress[i]):
            results.add(findipaddress[i])

    return results


def search_urls_in_str(urls):
    u = re.compile(r"(https?://[^ ]+)")

    found_urls = set([d.lower() for d in u.findall(urls)])

    return found_urls


def search_for_usable_info(values):
    results = dict(email=set(), ipaddresses=set(),
                   url=dict(twitter=list(), facebook=list(), other=list()), domain=list())

    if values:
        values = values.replace("\n", ' ')
        values = values.replace("\t", ' ')
        results['email'] = search_emailaddress_in_str(values)
        # results['domains'] = search_domainnames_in_str(values)
        results['ipaddresses'] = search_ipv4address_in_str(values)
        urls = search_urls_in_str(values)
        # return email, urls, domains, ipaddresses

        for url in urls:
            u = extract(url)
            if lower(u.domain) == 'twitter':
                acc = extract_twitter_acc(url)
                if acc:
                    results['url']['twitter'].append(acc)
                else:
                    results['url']['other'].append(url)
            elif lower(u.domain) == 'facebook':
                acc = extract_facebook_acc(url)
                if acc:
                    results['url']['facebook'].append(acc)
                else:
                    results['url']['other'].append(url)
            else:
                results['url']['other'].append(url)

    return results


# TODO Check this function
def extract_facebook_acc(url):
    # Parse url and query
    url = url.strip().rstrip('/')
    u = urlparse(url)
    uq = parse_qs(u[4])

    # IF path = /profile.php
    if u.path == '/profile.php':

        # Length can be 2 or 3 depends if user is integer or not
        if len(uq) == 2 or len(uq) == 3:
            try:
                return dict(name=''.join(uq['id']), url=url)

            except KeyError:
                pass

    elif u.query and len(u.path[1:].split('/')) == 1 and u.path[-4:] != '.php':
        return dict(name=u.path[1:], url='https://{}'.format(''.join(u[1:3])))

    elif not u.query and len(u.path[1:].split('/')) == 1 and u.path[-4:] != '.php':
        return dict(name=u.path[1:], url='https://{}'.format(''.join(u[1:3])))


def extract_twitter_acc(url):
    # Parse url
    u = urlparse(url)
    if len(u.path[1:].split('/')) == 1:
        return dict(name=u.path[1:], url=url)
