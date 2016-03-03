#!/usr/bin/env python
# -*- coding: utf-8 -*-

from canari.maltego.utils import debug
from canari.framework import configure
from common.entities import Indicator, Mutex
from canari.maltego.message import Label, UIMessage
from common.client import get_indicator, encode_to_utf8, upper, ThreatCentralError

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
    label='Indicator To Mutex',
    description='Get all Mutex linked to Indicator',
    uuids=['threatcentral.v2.IndicatorToMutex'],
    inputs=[('Threat Central', Indicator)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):
    if 'ThreatCentral.resourceId' in request.fields:
        try:
            indicator = get_indicator(request.fields['ThreatCentral.resourceId'])
        except ThreatCentralError as err:
            indicator = None
            response += UIMessage(err.value, type='PartialError')

        if indicator:
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
                        if upper(observable.get('type', dict()).get('value')) == 'MUTEX':
                            # Use sighting
                            if observable.get('sighting'):
                                weight = int(observable.get('sighting'))
                            else:
                                weight = 1

                            e = Mutex(observable.get('value'), weight=weight)
                            # TODO : Verify this
                            # e.name = observable.get('name')
                            e.value = observable.get('value')
                            # TODO : Verify this
                            # e.action = observable.get('action', dict()).get('displayName')
                            e.resourceId = observable.get('resourceId')

                            response += e

            except AttributeError as err:
                response += UIMessage('Error: {}'.format(err), type='PartialError')
            except ThreatCentralError as err:
                response += UIMessage(err.value, type='PartialError')
            except TypeError:
                return response

    return response

