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
from common.entities import Actor, Incident
from common.client import get_linked_incidents, encode_to_utf8, ThreatCentralError


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
    label='Get linked Incidents',
    description='Get linked Incidents from Threat Central',
    uuids=['threatcentral.v2.ActorToIncidents'],
    inputs=[('Threat Central', Actor)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):

    try:
        incidents = get_linked_incidents(request.fields['ThreatCentral.resourceId'])
    except ThreatCentralError as err:
        response += UIMessage(err.value, type='PartialError')
        return response
    except KeyError:
        response += UIMessage("No resourceId!", type='PartialError')
        return response
    else:
        try:
            for incident in incidents:
                if incident.get('tcScore'):
                    weight = int(incident.get('tcScore'))
                else:
                    weight = 1

                e = Incident(encode_to_utf8(incident.get('title')), weight=weight)
                e.title = encode_to_utf8(incident.get('title'))
                e.resourceId = incident.get('resourceId')
                e.reportedOn = incident.get('reportedOn')
                e += Label('Reported On', incident.get('reportedOn'))

                if len(incident.get('incidentCategory', list())) is not 0:
                    e += Label('Incident Category', '<br/>'.join([encode_to_utf8(_.get('displayName'))
                                                                 for _ in incident.get('incidentCategory',
                                                                                       list())]))

                if len(incident.get('affectedAsset', list())) is not 0:
                    e += Label('Affected Asset', '<br/>'.join([encode_to_utf8(_.get('displayName'))
                                                              for _ in incident.get('affectedAsset', list())]))

                if len(incident.get('incidentEffect', list())) is not 0:
                    e += Label('Incident Effect', '<br/>'.join([encode_to_utf8(_.get('displayName'))
                                                               for _ in incident.get('incidentEffect', list())]))

                if len(incident.get('discoveryMethod', list())) is not 0:
                    e += Label('Discovery Method', '<br/>'.join([encode_to_utf8(_.get('displayName'))
                                                                for _ in incident.get('discoveryMethod', list())]))

                if incident.get('description'):
                    e += Label('Description', '<br/>'.join(encode_to_utf8(incident.get('description')
                                                                          ).split('\n')))

                response += e

        except AttributeError as err:
            response += UIMessage('Error: {}'.format(err), type='PartialError')
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')
        except TypeError:
            return response

    return response
