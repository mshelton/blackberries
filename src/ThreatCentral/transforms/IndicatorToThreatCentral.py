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
from common.entities import Case, Indicator, Actor, TTP, CoursesOfAction
from common.client import search_indicator, get_indicator, encode_to_utf8, lower, ThreatCentralError


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
    label='Search Indicator in Threat Central',
    description='Searches Indicator in Threat Central',
    uuids=['threatcentral.v2.IndicatorToThreatCentral'],
    inputs=[('Threat Central', Indicator)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):
    try:
        indicator = get_indicator(request.fields['ThreatCentral.resourceId'])
    except ThreatCentralError as err:
        response += UIMessage(err.value, type='PartialError')
        return response
    except KeyError:
        try:
            indicators = search_indicator(request.value)
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')
            return response
        else:
            try:
                for indicator in indicators:
                    if indicator.get('tcScore'):
                        weight = int(indicator.get('tcScore'))
                    else:
                        weight = 1
                    indicator = indicator.get('resource')
                    e = Indicator(encode_to_utf8(indicator.get('title')), weight=weight)
                    e.title = encode_to_utf8(indicator.get('title'))
                    e.resourceId = indicator.get('resourceId')

                    if indicator.get('severity'):
                        e += Label('Severity', indicator.get('severity', dict()).get('displayName'))
                        e.severity = indicator.get('severity', dict()).get('displayName')
                    if indicator.get('confidence'):
                        e += Label('Confidence', indicator.get('confidence', dict()).get('displayName'))
                        e.confidence = indicator.get('confidence', dict()).get('displayName')
                    if indicator.get('indicatorType'):
                        e += Label('Indicator Type', indicator.get('indicatorType', dict()).get('displayName'))
                        e.indicatorType = indicator.get('indicatorType', dict()).get('displayName')
                    if indicator.get('description'):
                        e += Label('Description', '<br/>'.join(encode_to_utf8(indicator.get('description')
                                                                              ).split('\n')))

                    response += e

            except AttributeError as err:
                response += UIMessage('Error: {}'.format(err), type='PartialError')
            except ThreatCentralError as err:
                response += UIMessage(err.value, type='PartialError')
            except TypeError:
                return response
    else:

        if indicator:
            try:
                if indicator.get('tcScore'):
                    weight = int(indicator.get('tcScore'))
                else:
                    weight = 1
                # Update Indicator entity
                e = Indicator(request.value, weight=weight)
                e.title = encode_to_utf8(indicator.get('title'))
                e.resourceId = indicator.get('resourceId')

                e += Label('Severity', indicator.get('severity', dict()).get('displayName'))
                e += Label('Confidence', indicator.get('confidence', dict()).get('displayName'))
                e += Label('Indicator Type', indicator.get('indicatorType', dict()).get('displayName'))

                if indicator.get('description'):
                    e += Label('Description', '<br/>'.join(encode_to_utf8(indicator.get('description')
                                                                          ).split('\n')))

                response += e
            except AttributeError as err:
                response += UIMessage('Error: {}'.format(err), type='PartialError')
            except ThreatCentralError as err:
                response += UIMessage(err.value, type='PartialError')
            except TypeError:
                return response

    return response
