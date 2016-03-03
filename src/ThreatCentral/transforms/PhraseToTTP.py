#!/usr/bin/env python

from canari.maltego.utils import debug
from canari.framework import configure
from canari.maltego.entities import Phrase
from canari.maltego.message import Label, UIMessage
from common.entities import TTP
from common.client import search_ttp, encode_to_utf8, ThreatCentralError

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
    label='Search Phrase in TTP',
    description='Search Tactics Techniques And Procedures in Threat Central',
    uuids=['threatcentral.v2.PhraseToTTP'],
    inputs=[('Threat Central', Phrase)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):

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

    return response
