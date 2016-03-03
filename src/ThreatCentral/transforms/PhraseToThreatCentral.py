#!/usr/bin/env python

# (c) Copyright [2016] Hewlett Packard Enterprise Development LP Licensed under
# the Apache License, Version 2.0 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of the License
# at  Unless required by applicable
# law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

from canari.maltego.utils import debug
from canari.framework import configure
from canari.maltego.entities import Phrase
from canari.maltego.message import Label, UIMessage
from common.entities import Case, Incident, Indicator, Actor, TTP, CoursesOfAction
from common.client import search, encode_to_utf8, lower, ThreatCentralError


__author__ = 'Bart Otten'
__copyright__ = '(c) Copyright [2016] Hewlett Packard Enterprise Development LP'
__credits__ = []

__license__ = 'Apache 2.0'
__version__ = '1'
__maintainer__ = 'Bart Otten'
__email__ = 'tc-support@hpe.com'
__status__ = 'Development'

__all__ = [
    'dotransform'
]


@configure(
    label='Search Phrase in Threat Central',
    description='Searches Phrase in Threat Central',
    uuids=['threatcentral.v2.PhraseToThreatCentral'],
    inputs=[('Threat Central', Phrase)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):

    try:
        results = search(request.value)
    except ThreatCentralError as err:
        response += UIMessage(err.value, type='PartialError')
    else:
        try:
            for result in results:
                rtype = lower(result.get('type'))

                if result.get('tcScore'):
                    weight = int(result.get('tcScore'))
                else:
                    weight = 1

                # Title ID Description
                if rtype == 'actor':
                    # Check Title, if no title get resource > name
                    # Actor entity can have an empty title field
                    if result.get('title'):
                        e = Actor(encode_to_utf8(result.get('title')), weight=weight)
                    else:
                        e = Actor(encode_to_utf8(result.get('resource', dict()).get('name')), weight=weight)
                        e.name = encode_to_utf8(result.get('resource', dict()).get('name'))
                        e.actor = encode_to_utf8(result.get('resource', dict()).get('name'))
                elif rtype == 'case':
                    e = Case(encode_to_utf8(result.get('title')), weight=weight)
                elif rtype == 'coursesofactions':
                    e = CoursesOfAction(encode_to_utf8(result.get('title')), weight=weight)
                elif rtype == 'indicator':
                    e = Indicator(encode_to_utf8(result.get('title')), weight=weight)
                elif rtype == 'incident':
                    e = Incident(encode_to_utf8(result.get('title')), weight=weight)
                # elif rtype == 'tacticstechniquesandprocedures':
                elif rtype == 'ttp':
                    e = TTP(encode_to_utf8(result.get('title')), weight=weight)
                else:
                    # To be safe
                    e = Phrase(encode_to_utf8(result.get('title')), weight=weight)
                    debug(rtype)

                e.title = encode_to_utf8(result.get('title'))
                e.resourceId = result.get('id')

                if result.get('description'):
                    e += Label('Description', '<br/>'.join(encode_to_utf8(result.get('description',
                                                                                     '')).split('\n')))

                response += e

        except AttributeError as err:
            response += UIMessage('Error: {}'.format(err), type='PartialError')
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')
        except TypeError:
            return response
    return response
