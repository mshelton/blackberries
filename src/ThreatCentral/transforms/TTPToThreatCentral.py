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
from canari.maltego.message import Label, UIMessage
from common.entities import TTP
from common.client import search_ttp, get_ttp, encode_to_utf8, ThreatCentralError


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
    label='Search TTP in Threat Central',
    description='Searches TTP in Threat Central',
    uuids=['threatcentral.v2.TTPToThreatCentral'],
    inputs=[('Threat Central', TTP)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):

    try:
        ttp = get_ttp(request.fields['ThreatCentral.resourceId'])
    except ThreatCentralError as err:
        response += UIMessage(err.value, type='PartialError')
        return response
    except KeyError:
        try:
            ttps = search_ttp(request.value)
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')
            return response
        else:
            try:
                for ttp in ttps:
                    if ttp.get('tcScore'):
                        weight = int(ttp.get('tcScore'))
                    else:
                        weight = 1
                    e = TTP(encode_to_utf8(ttp.get('title')), weight=weight)
                    e.title = encode_to_utf8(ttp.get('title'))
                    e.resourceId = ttp.get('id')
                    response += e

            except AttributeError as err:
                response += UIMessage('Error: {}'.format(err), type='PartialError')
            except ThreatCentralError as err:
                response += UIMessage(err.value, type='PartialError')
            except TypeError:
                return response
    else:
        if ttp:
            # IF we have an resourceID return the
            try:
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

    return response
