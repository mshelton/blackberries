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
from common.entities import Incident, TTP
from canari.maltego.message import UIMessage
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
    label='Get linked TTPs',
    description='Get linked TTPs from Threat Central',
    uuids=['threatcentral.v2.IncidentToTTP'],
    inputs=[('Threat Central', Incident)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):

    if 'ThreatCentral.resourceId' in request.fields:
        try:
            incident = get_incident(request.fields['ThreatCentral.resourceId'])
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')
        else:
            try:
                # Show linked TTP's
                if len(incident.get('tacticsTechniquesAndProcedures', list())) is not 0:
                    for ttp in incident.get('tacticsTechniquesAndProcedures'):
                        if ttp.get('tcScore'):
                            weight = int(ttp.get('tcScore'))
                        else:
                            weight = 1

                        e = TTP(encode_to_utf8(ttp.get('title')), weight=weight)
                        e.title = encode_to_utf8(ttp.get('title'))
                        e.resourceId = ttp.get('resourceId')
                        response += e

            except AttributeError as err:
                response += UIMessage('Error: {}'.format(err), type='PartialError')
            except ThreatCentralError as err:
                response += UIMessage(err.value, type='PartialError')
            except TypeError:
                return response

    return response
