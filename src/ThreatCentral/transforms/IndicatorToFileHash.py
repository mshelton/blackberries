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
from common.entities import Indicator, FileHash
from canari.maltego.message import Label, UIMessage
from common.client import get_indicator, encode_to_utf8, upper, ThreatCentralError

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
    label='Indicator To File Hash',
    description='Get all File Hashes linked to Indicator',
    uuids=['threatcentral.v2.IndicatorToFileHash'],
    inputs=[('Threat Central', Indicator)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):
    if 'ThreatCentral.resourceId' in request.fields:
        try:
            indicator = get_indicator(request.fields['ThreatCentral.resourceId'])
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')
        else:
            try:
                # Update Indicator entity ?
                e = Indicator(request.value)
                e.title = encode_to_utf8(indicator.get('title'))
                e.resourceId = indicator.get('resourceId')
                e.severity = indicator.get('severity', dict()).get('displayName')
                e.confidence = indicator.get('confidence', dict()).get('displayName')
                e.indicatorType = indicator.get('indicatorType', dict()).get('displayName')

                e += Label('Severity', indicator.get('severity', dict()).get('displayName'))
                e += Label('Confidence', indicator.get('confidence', dict()).get('displayName'))
                e += Label('Indicator Type', indicator.get('indicatorType', dict()).get('displayName'))

                if indicator.get('description'):
                    e += Label('Description', '<br/>'.join(encode_to_utf8(indicator.get('description')
                                                                          ).split('\n')))
                response += e

                if len(indicator.get('observables', list())) is not 0:
                    for observable in indicator.get('observables'):
                        if upper(observable.get('type', dict()).get('value')) == 'FILE_HASH':
                            # Use sighting
                            if observable.get('sighting'):
                                weight = int(observable.get('sighting'))
                            else:
                                weight = 1

                            filehashes = observable.get('fileHashes', list())
                            for filehash in filehashes:
                                e = FileHash(filehash.get('value'), weight=weight)
                                #e.name = observable.get('name')
                                e.value = filehash.get('value')
                                e.htype = filehash.get('type')
                                e.resourceId = observable.get('resourceId')

                                response += e

            except AttributeError as err:
                response += UIMessage('Error: {}'.format(err), type='PartialError')
            except ThreatCentralError as err:
                response += UIMessage(err.value, type='PartialError')
            except TypeError:
                return response

    return response

