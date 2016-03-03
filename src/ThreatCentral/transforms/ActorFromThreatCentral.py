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
from canari.maltego.entities import Twitter, Facebook, URL, EmailAddress, Location, Domain
from common.entities import Actor
from canari.maltego.message import Label, UIMessage
from common.client import get_actor, encode_to_utf8, search_for_usable_info, ThreatCentralError

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
    label='Get Actor Details',
    description='Get details about Actor from Threat Central',
    uuids=['threatcentral.v2.ActorFromThreatCentral'],
    inputs=[('Threat Central', Actor)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):

    notes = list()

    if 'ThreatCentral.resourceId' in request.fields:
        try:
            actor = get_actor(request.fields['ThreatCentral.resourceId'])
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')
        else:
            try:
                # Update entity?
                e = Actor(request.value)
                if actor.get('name'):
                    e.name = encode_to_utf8(actor.get('name'))
                    e.actor = encode_to_utf8(actor.get('name'))

                e.title = encode_to_utf8(actor.get('title'))
                e.resourceId = actor.get('resourceId')
                if actor.get('organization'):
                    e.organization = encode_to_utf8(actor.get('organization'))
                if actor.get('aliases'):
                    e.aliases = ', '.join([encode_to_utf8(_) for _ in actor.get('aliases')])
                if actor.get('country'):
                    e.country = encode_to_utf8(actor.get('country', dict()).get('displayName'))
                    # Add Location entitie
                    l = Location(encode_to_utf8(actor.get('country', dict()).get('displayName')))
                    response += l
                if actor.get('score'):
                    e.score = actor.get('score')

                if actor.get('links'):
                    e += Label('Links', '<br/>'.join(['<a href="{}">{}</a>'.format(_.get('href'), _.get('href'))
                                                      for _ in actor.get('links')]))
                if actor.get('hyperlinks'):
                    e += Label('Hyperlinks', '<br/>'.join(['<a href="{}">{}</a>'.format(_.get('url'), _.get('title'))
                                                           for _ in actor.get('hyperlinks')]))

                if actor.get('title'):
                    e += Label('Title', encode_to_utf8(actor.get('title')))
                if actor.get('resourceId'):
                    e += Label('ResourceID', actor.get('resourceId'))
                if actor.get('aliases'):
                    e += Label('Aliases', '<br/>'.join([encode_to_utf8(_) for _ in actor.get('aliases', '')]))
                if actor.get('description'):
                    e += Label('Description', '<br/>'.join(encode_to_utf8(actor.get('description', '')).split('\n')))
                if actor.get('country'):
                    e += Label('Country', encode_to_utf8(actor.get('country', dict()).get('displayName')))
                if actor.get('organization'):
                    e += Label('Organization', encode_to_utf8(actor.get('organization')))
                if actor.get('types'):
                    e += Label('Types', '<br/>'.join([encode_to_utf8(_.get('displayName'))
                                                     for _ in actor.get('types')]))

                if actor.get('motivations'):
                    e += Label('Motivations', '<br/>'.join([encode_to_utf8(_.get('displayName'))
                                                            for _ in actor.get('motivations')]))
                if actor.get('intendedEffects'):
                    e += Label('Intended Effects', '<br/>'.join([encode_to_utf8(_.get('displayName'))
                                                                 for _ in actor.get('intendedEffects')]))
                if actor.get('sophistication'):
                    e += Label('Sophistication', encode_to_utf8(actor.get('sophistication', dict()).get('displayName')))
                if actor.get('socialMediaText'):
                    e += Label('Social Media', '<br/>'.join(encode_to_utf8(actor.get('socialMediaText', '')
                                                                           ).split('\n')))
                if actor.get('moreInfo'):
                    e += Label('More Info', '<br/>'.join(encode_to_utf8(actor.get('moreInfo', '')).split('\n')))

                if actor.get('score'):
                    e += Label('Score', actor.get('score'))

                response += e

                # Extract email addresses
                usable_info = search_for_usable_info(
                    '{} {} {}'.format(encode_to_utf8(actor.get('description')),
                                      encode_to_utf8(actor.get('socialMediaText')),
                                      encode_to_utf8(actor.get('moreInfo'))))
                if usable_info:
                    debug(usable_info)
                    try:
                        urls = usable_info.get('url', dict())
                        for twitter in urls.get('twitter', list()):
                            t = Twitter(twitter.get('name'))
                            t.uid = twitter.get('name')
                            t.set_field('affiliation.profile-url', twitter.get('url'))
                            response += t

                        for facebook in urls.get('facebook', list()):
                            f = Facebook(facebook.get('name'))
                            f.uid = facebook.get('name')
                            f.set_field('affiliation.profile-url', facebook.get('url'))
                            response += f

                        for other in urls.get('other', list()):
                            u = URL(other)
                            u.url = other
                            response += u

                        emailaddr = usable_info.get('email', list())
                        for email in emailaddr:
                            e = EmailAddress(email)
                            response += e

                    except AttributeError as err:
                        response += UIMessage('Error: {}'.format(err))

            except AttributeError as err:
                response += UIMessage('Error: {}'.format(err), type='PartialError')
            except ThreatCentralError as err:
                response += UIMessage(err.value, type='PartialError')
            except TypeError:
                return response

    return response
