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
from common.entities import Case, Hyperlinks, Attachments
from canari.maltego.message import Label, UIMessage
from common.client import get_case, encode_to_utf8, ThreatCentralError

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
    label='Get Case Details',
    description='Get Case Details from Threat Central',
    uuids=['threatcentral.v2.CaseFromThreatCentral'],
    inputs=[('Threat Central', Case)],
    debug=False,
    remote=False
)
def dotransform(request, response, config):
    if 'ThreatCentral.resourceId' in request.fields:
        try:
            case = get_case(request.fields['ThreatCentral.resourceId'])
        except ThreatCentralError as err:
            response += UIMessage(err.value, type='PartialError')

        else:
            try:
                # Update entity?
                e = Case(request.value)
                if case.get('title'):
                    e.case = encode_to_utf8(case.get('title'))
                    e.title = encode_to_utf8(case.get('title'))
                    e += Label('Title', encode_to_utf8(case.get('title')))
                if case.get('resourceId'):
                    e += Label('ResourceID', case.get('resourceId'))
                if case.get('description'):
                    e += Label('Description', '<br/>'.join(encode_to_utf8(case.get('description', '')).split('\n')))
                if case.get('importanceScore'):
                    e.importanceScore = case.get('importanceScore')
                    e += Label('Importance Score', case.get('importanceScore'))
                if case.get('importanceLevel'):
                    e.importanceLevel = case.get('importanceLevel')
                    e += Label('Importance Level', case.get('importanceLevel'))

                # Show comments
                if len(case.get('comments', list())) is not 0:
                    e += Label('Comments', '<br/>'.join(['{}<br/>'.format(_.get('text'))
                                                         for _ in encode_to_utf8(case.get('comments'))]))

                response += e

                # Show Hyperlinks
                if len(case.get('hyperlinks', list())) is not 0:
                    for hyperlink in case.get('hyperlinks'):
                        e = Hyperlinks(encode_to_utf8(hyperlink.get('title')))
                        e.title = encode_to_utf8(hyperlink.get('title'))
                        e.resourceId = hyperlink.get('resourceId')
                        e.url = hyperlink.get('url')
                        e += Label('Title', encode_to_utf8(hyperlink.get('title')))
                        e += Label('Resource ID', hyperlink.get('resourceId'))
                        e += Label('url', hyperlink.get('url'))

                        response += e

                # Show Attachments
                if len(case.get('attachments', list())) is not 0:
                    for attachment in case.get('attachments'):
                        e = Attachments(encode_to_utf8(attachment.get('name')))
                        e.name = encode_to_utf8(attachment.get('name'))
                        e.resourceId = attachment.get('resourceId')
                        e.atype = attachment.get('type')
                        e.size = attachment.get('size')
                        e.checksum = attachment.get('checksum')
                        e.createDate = attachment.get('createDate')
                        if attachment.get('description'):
                            e += Label('Description', '<br/>'.join(encode_to_utf8(attachment.get('description')
                                                                                  ).split('\n')))
                        if len(attachment.get('links', list())) is not 0:
                            for att in attachment.get('links', list()):
                                e += Label('Links', '<a href="{}">{}</a><br/>'.format(att.get('href'), att.get('href')))

                        response += e

            except AttributeError as err:
                response += UIMessage('Error: {}'.format(err), type='PartialError')
            except ThreatCentralError as err:
                response += UIMessage(err.value, type='PartialError')
            except TypeError:
                return response

    return response
