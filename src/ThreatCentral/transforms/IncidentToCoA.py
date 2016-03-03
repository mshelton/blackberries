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
from common.entities import Incident, CoursesOfAction
from canari.maltego.message import Label, UIMessage
from common.client import get_incident, encode_to_utf8, ThreatCentralError

__author__ = 'Bart Otten'
__copyright__ = 'Copyright 2015, Threat Central'
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
    label='Get linked Courses of Actions',
    description='Get linked Courses of Actions from Threat Central',
    uuids=['threatcentral.v2.IncidentToCoA'],
    inputs=[('Threat Central', Incident)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):

    if 'ThreatCentral.resourceId' in request.fields:
        try:
            coa = get_incident(request.fields['ThreatCentral.resourceId'])
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')
        else:
            try:
                # Show linked Courses Of Actions
                if len(coa.get('coursesOfAction', list())) is not 0:
                    for coa in coa.get('coursesOfAction'):
                        if coa.get('tcScore'):
                            weight = int(coa.get('tcScore'))
                        else:
                            weight = 1

                        e = CoursesOfAction(encode_to_utf8(coa.get('title')), weight=weight)
                        e.title = encode_to_utf8(coa.get('title'))
                        e += Label('Title', encode_to_utf8(coa.get('title')))
                        e.resourceId = coa.get('resourceId')

                        if coa.get('description'):
                            e += Label('Description', '<br/>'.join(encode_to_utf8(coa.get('description')
                                                                                  ).split('\n')))

                        response += e

            except AttributeError as err:
                response += UIMessage('Error: {}'.format(err), type='PartialError')
            except ThreatCentralError as err:
                response += UIMessage(err.value, type='PartialError')
            except TypeError:
                return response

    return response
