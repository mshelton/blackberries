#!/usr/bin/env python
# -*- coding: utf-8 -*-

from canari.maltego.utils import debug
from canari.framework import configure
from common.entities import Indicator, Incident
from canari.maltego.message import Label, UIMessage
from common.client import get_incident, encode_to_utf8, ThreatCentralError

__author__ = 'Bart Otten'
__copyright__ = 'Copyright 2015, Threat Central Project'
__credits__ = []

__license__ = 'Apache 2.0'
__version__ = '1'
__maintainer__ = 'Bart Otten'
__email__ = 'bart.otten@hp.com'
__status__ = 'Development'

__all__ = [
    'dotransform'
]


@configure(
    label='Get linked Indicators',
    description='Get linked Indicator from Threat Central',
    uuids=['threatcentral.v2.IncidentToIndicators'],
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
                for indicator in incident.get('indicators'):
                    if indicator.get('tcScore'):
                        weight = int(indicator.get('tcScore'))
                    else:
                        weight = 1

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

    return response
