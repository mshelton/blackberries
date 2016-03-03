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

from canari.maltego.utils import debug
from canari.framework import configure
from canari.maltego.entities import Phrase
from common.entities import Case
from canari.maltego.message import Label, UIMessage
from common.client import search_case, encode_to_utf8, ThreatCentralError

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
    label='Search Phrase in Cases',
    description='Search Phrase on Threat Central and filter on cases',
    uuids=['threatcentral.v2.PhraseToCase'],
    inputs=[('Threat Central', Phrase)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):

    try:
        cases = search_case(request.value)
    except ThreatCentralError as err:
        response += UIMessage(err.value, type='PartialError')

    else:
        try:
            for case in cases:
                if case.get('tcScore'):
                    weight = int(case.get('tcScore'))
                else:
                    weight = 1
                e = Case(encode_to_utf8(case.get('title')), weight=weight)
                e.title = encode_to_utf8(case.get('title'))
                # e.resourceId = indicator.get('resourceId')
                e.resourceId = case.get('id')

                if case.get('importanceScore'):
                    e.importanceScore = case.get('importanceScore')
                    e += Label('Importance Score', case.get('importanceScore'))
                if case.get('importanceLevel'):
                    e.importanceLevel = case.get('importanceLevel')
                    e += Label('Importance Level', case.get('importanceLevel'))

                # Show comments
                if len(case.get('comments', list())) is not 0:
                    e += Label('Comments', '<br/>'.join(['{}<br/>'.format(_.get('text'))
                                                         for _ in encode_to_utf8(case.get('comments'))]))
                if case.get('description'):
                    e += Label('Description', '<br/>'.join(encode_to_utf8(case.get('description')
                                                                          ).split('\n')))

                response += e

        except AttributeError as err:
            response += UIMessage('Error: {}'.format(err), type='PartialError')
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')
        except TypeError:
            return response

    return response
