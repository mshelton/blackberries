#!/usr/bin/env python

from canari.maltego.utils import debug
from canari.framework import configure
from canari.maltego.entities import Phrase
from canari.maltego.message import Label, UIMessage
from common.entities import Comment, Actor, Case, CoursesOfAction, Incident, Indicator, TTP
from common.client import search, encode_to_utf8, lower, ThreatCentralError


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
    label='Search Comment in Threat Central',
    description='Searches Comment in Threat Central',
    uuids=['threatcentral.v2.CommentToThreatCentral'],
    inputs=[('Threat Central', Comment)],
    debug=False,
    remote=False
)
# TODO : This transform works the same as Phrase to Threat Central
def dotransform(request, response, config):

    try:
        results = search(request.value, size=10, pages=1)
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
