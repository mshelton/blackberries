#!/usr/bin/env python

# (c) Copyright [2016] Hewlett Packard Enterprise Development LP Licensed under
# the Apache License, Version 2.0 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of the License
# at  Unless required by applicable
# law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

import requests
from time import sleep
from random import seed, random
from json import dumps
# from urlparse import urlparse


__author__ = 'Bart Otten'
__copyright__ = '(c) Copyright [2016] Hewlett Packard Enterprise Development LP'
__credits__ = []

__license__ = 'Apache 2.0'
__version__ = '1'
__maintainer__ = 'Bart Otten'
__email__ = 'tc-support@hpe.com'
__status__ = 'Development'


class ThreatCentralError(Exception):

    def __init__(self, what, value):
        if what == 'login':
            self.value = 'Error logging into Threat Central : {}'.format(value)
        elif what == 'connection':
            self.value = 'Error connecting to Threat Central : {}'.format(value)
        elif what == 'response':
            self.value = 'Received wrong response from Threat Central : {}'.format(value)
        elif what == 'apikey':
            self.value = 'Error receiving API Key from Threat Central : {}'.format(value)
        else:
            self.value = 'Threat Central : {}'.format(value)

    def __str__(self):
        return repr(self.value)


# Filter : valid values: indicators, incidents, actors, ttps, cases, all

class ThreatCentral:

    auth = None

    # cache_folder = '/tmp/ThreatCentral/cache/'

    api_url = 'https://threatcentral.io/tc/rest/users/me/api-keys'
    api_name = 'ThreatCentalToMaltego'

    indicator_url = 'https://threatcentral.io/tc/rest/indicators/'
    incidents_url = 'https://threatcentral.io/tc/rest/incidents/'
    summaries_url = 'https://threatcentral.io/tc/rest/summaries/'
    actors_url = 'https://threatcentral.io/tc/rest/actors/'
    cases_url = 'https://threatcentral.io/tc/rest/cases/'
    ttp_url = 'https://threatcentral.io/tc/rest/tactics-techniques-and-procedures/'

    stixId = '?stixId='
    value = '?value='
    title = '?title='
    text = '?text='
    entities = '&entities='
    hateoas = '&hateoas='
    observable_types = '&observableTypes='
    last_updated = '&lastUpdated='
    page = '&page='
    size = '&size='
    exactmatch = '&exactMatch='
    linkedentityid = '?linkedEntityId='

    indicator = ''
    incident = ''
    actor = ''
    case = ''
    ttp = ''

    content = None

    # Default values
    cur_page = dict(
        size=50,
        totalElements=0,
        totalPages=0,
        number=0
    )

    timeout = 60

    def __init__(self):
        pass

    def get_request(self, url):

        try:
            r = requests.get(url, auth=self.auth, timeout=self.timeout)
        except requests.ConnectionError as e:
            raise ThreatCentralError('connection', e)
        except requests.Timeout as e:
            raise ThreatCentralError('connection', e)
        else:
            if r.status_code == 200:
                try:
                    return r.json()
                except ValueError:
                    raise ThreatCentralError('connection', 'No valid JSON returned')
            else:
                raise ThreatCentralError('connection', 'Status code: {}'.format(r.status_code))

    def post_request(self, url, data):
        headers = {'Content-Type': 'application/json'}

        try:
            r = requests.post(url, data=data, auth=self.auth, headers=headers)
        except requests.ConnectionError as e:
            raise ThreatCentralError('connection', e)

        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                raise ThreatCentralError('connection', 'No valid JSON returned')
        else:
            raise ThreatCentralError('connection', 'Status code: {}'.format(r.status_code))

    def __search__(self, url, param, value, last_updated=None, entities=None, observable_types=None, hateoas=False,
                   exactmatch=False, pages=0):

        url = [url, param, value]

        if entities:
            url.extend([self.entities, ','.join(entities)])

        if observable_types:
            url.extend([self.observable_types, ','.join(observable_types)])

        if last_updated:
            url.extend([self.last_updated, last_updated])

        # Disables fuzzy searching
        if exactmatch:
            url.extend([self.exactmatch, str(exactmatch)])

        url = ''.join(url)

        while True:

            self.content = self.get_request(''.join((url, self.hateoas, str(hateoas),
                                                     self.page, str(self.cur_page['number']),
                                                     self.size, str(self.cur_page['size'])
                                                     )))

            if self.content:
                try:
                    self.cur_page = dict(size=self.content['page']['size'],
                                         totalElements=self.content['page']['totalElements'],
                                         totalPages=self.content['page']['totalPages'],
                                         number=self.content['page']['number'])

                    for content in self.content.get('content', list()):
                        yield content

                except KeyError as e:
                    raise ThreatCentralError('response', e)

            # No content, break
            else:
                break

            if 1 < self.cur_page['totalPages'] and self.cur_page['totalPages'] > self.cur_page['number']:
                if pages == 0 or self.cur_page['number'] < pages:
                    self.cur_page['number'] += 1
                else:
                    break
            else:
                break

    def __get_item__(self, url, value):
        self.content = self.get_request(''.join((url, value)))
        if self.content:
            return self.content

    def __get_linked_items__(self, url, value, hateoas=False, pages=0):
        # self.content = self.get_request(''.join((url, self.linkedentityid, value, self.hateoas, str(hateoas))))
        while True:

            self.content = self.get_request(''.join((url, self.linkedentityid, value, self.hateoas, str(hateoas),
                                                     self.page, str(self.cur_page['number']),
                                                     self.size, str(self.cur_page['size'])
                                                     )))

            if self.content:
                try:
                    self.cur_page = dict(size=self.content['page']['size'],
                                         totalElements=self.content['page']['totalElements'],
                                         totalPages=self.content['page']['totalPages'],
                                         number=self.content['page']['number'])

                    for content in self.content.get('content', list()):
                        yield content

                except KeyError as e:
                    raise ThreatCentralError('response', e)

            # No content, break
            else:
                break

            if 1 < self.cur_page['totalPages'] and self.cur_page['totalPages'] > self.cur_page['number']:
                if pages == 0 or self.cur_page['number'] < pages:
                    self.cur_page['number'] += 1
                else:
                    break
            else:
                break

    def search(self, value, observable_types=None, filters=None, last_updated=None, exactmatch=False, pages=0):
        return self.__search__(self.summaries_url, self.text, value,
                               observable_types=observable_types, last_updated=last_updated,
                               entities=filters, exactmatch=exactmatch, pages=pages)

    def search_title(self, value, exactmatch=False, pages=0):
        return self.__search__(self.summaries_url, self.title, value, exactmatch=exactmatch, pages=pages)

    def search_indicator(self, value, exactmatch=False, pages=0):
        # Filter on Indicators
        return self.__search__(self.summaries_url, self.text, value, entities=['Indicators'], exactmatch=exactmatch,
                               pages=pages)

    def search_actor(self, value, exactmatch=False, pages=0):
        # Filter on Actors
        return self.__search__(self.summaries_url, self.text, value, entities=['Actors'], exactmatch=exactmatch,
                               pages=pages)

    def search_case(self, value, exactmatch=False, pages=0):
        # Filter on Cases
        return self.__search__(self.summaries_url, self.text, value, entities=['Cases'], exactmatch=exactmatch,
                               pages=pages)

    def search_ttp(self, value, exactmatch=False, pages=0):
        # Filter on TTPs
        return self.__search__(self.summaries_url, self.text, value, entities=['ttps'], exactmatch=exactmatch,
                               pages=pages)

    def search_incident(self, value, exactmatch=False, pages=0):
        # Filter on Incident
        return self.__search__(self.summaries_url, self.text, value, entities=['Incidents'], exactmatch=exactmatch,
                               pages=pages)

    def get_actor(self, value):
        return self.__get_item__(self.actors_url, value)

    def get_case(self, value):
        return self.__get_item__(self.cases_url, value)

    def get_indicator(self, value):
        return self.__get_item__(self.indicator_url, value)

    def get_incident(self, value):
        return self.__get_item__(self.incidents_url, value)

    def get_ttp(self, value):
        return self.__get_item__(self.ttp_url, value)

    def get_linked_actors(self, value):
        return self.__get_linked_items__(self.actors_url, value)

    def get_linked_cases(self, value):
        return self.__get_linked_items__(self.cases_url, value)

    def get_linked_indicators(self, value):
        return self.__get_linked_items__(self.indicator_url, value)

    def get_linked_incidents(self, value):
        return self.__get_linked_items__(self.incidents_url, value)

    def generate_api_key(self):
        payload = {'name': self.api_name}
        try:
            r = self.post_request(url=self.api_url, data=dumps(payload))
            return r['apiKey'], r['name']
        except KeyError:
            raise ThreatCentralError('apikey', 'apikey missing')

if __name__ == '__main__':
    pass
