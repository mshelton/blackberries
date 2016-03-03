#!/usr/bin/env python

# (c) Copyright [2016] Hewlett Packard Enterprise Development LP Licensed under
# the Apache License, Version 2.0 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of the License
# at  Unless required by applicable
# law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

from canari.maltego.message import Entity, EntityField, EntityFieldType, MatchingRule

__author__ = 'Bart Otten'
__copyright__ = '(c) Copyright [2016] Hewlett Packard Enterprise Development LP'
__credits__ = []

__license__ = 'Apache 2.0'
__version__ = '1'
__maintainer__ = 'Bart Otten'
__email__ = 'tc-support@hpe.com'
__status__ = 'Development'

__all__ = [
    'ThreatcentralEntity',
    'MyThreatcentralEntity'
]


"""
DO NOT EDIT:
The following entity is the base entity type from which all your entities will inherit from. This provides you with the
default namespace that all your entities will use for their unique entity type in Maltego. For example, MyThreatcentralEntity will
have an entity type name of ThreatCentral.MyThreatcentralEntity. When adding a new entity in Maltego, you will have to specify this
name (ThreatCentral.MyThreatcentralEntity) in the 'Unique entity type' field.
"""
class ThreatcentralEntity(Entity):
    _namespace_ = 'ThreatCentral'


"""
You can specify as many entity fields as you want by just adding an extra @EntityField() decorator to your entities. The
@EntityField() decorator takes the following parameters:
    - name: the name of the field without spaces or special characters except for dots ('.') (required)
    - propname: the name of the object's property used to get and set the value of the field (required, if name contains dots)
    - displayname: the name of the entity as it appears in Maltego (optional)
    - type: the data type of the field (optional, default: EntityFieldType.String)
    - required: whether or not the field's value must be set before sending back the message (optional, default: False)
    - choices: a list of acceptable field values for this field (optional)
    - matchingrule: whether or not the field should be loosely or strictly matched (optional, default: MatchingRule.Strict)
    - decorator: a function that is invoked each and everytime the field's value is set or changed.
    - is_value: a boolean value that determines whether the field is also the default value of the entity object.
TODO: define as many custom fields and entity types as you wish:)
"""


@EntityField(name='ThreatCentral.fieldN', propname='fieldN', displayname='Field N', matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.field1', propname='field1', displayname='Field 1', type=EntityFieldType.Integer)
class MyThreatcentralEntity(ThreatcentralEntity):
    """
    Uncomment the line below and comment out the pass if you wish to define a ridiculous entity type name like
    'my.fancy.EntityType'
    """
    # _name_ = 'my.fancy.EntityType'
    pass


@EntityField(name='ThreatCentral.actor', propname='actor', displayname='Actor',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.name', propname='name', displayname='Name',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.organization', propname='organization', displayname='Organization',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.aliases', propname='aliases', displayname='Aliases',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.country', propname='country', displayname='Country',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.score', propname='score', displayname='Score',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.title', propname='title', displayname='Title',
             matchingrule=MatchingRule.Loose)
class Actor(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.TTP', propname='TTP', displayname='Title',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
class TTP(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.title', propname='title', displayname='Title',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.severity', propname='severity', displayname='Severity',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.confidence', propname='confidence', displayname='Confidence',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.indicatorType', propname='indicatorType', displayname='Indicator Type',
             matchingrule=MatchingRule.Loose)
class Indicator(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.title', propname='title', displayname='Title',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.importanceScore', propname='importanceScore', displayname='ImportanceScore',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.importanceLevel', propname='importanceLevel', displayname='importanceLevel',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.indicatorType', propname='indicatorType', displayname='Indicator Type',
             matchingrule=MatchingRule.Loose)
class Case(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.title', propname='title', displayname='Title',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.url', propname='url', displayname='URL',
             matchingrule=MatchingRule.Loose)
class Hyperlinks(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.title', propname='title', displayname='Title',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
class CoursesOfAction(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.name', propname='name', displayname='Name',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.atype', propname='atype', displayname='Type',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.size', propname='size', displayname='Size',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.checksum', propname='checksum', displayname='Checksum',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.createDate', propname='createDate', displayname='Create Date',
             matchingrule=MatchingRule.Loose)
class Attachments(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.title', propname='title', displayname='Title',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.reportedOn', propname='reportedOn', displayname='Reported On',
             matchingrule=MatchingRule.Loose)
class Incident(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.postDate', propname='postDate', displayname='Post Data',
             matchingrule=MatchingRule.Loose)
class Comment(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.name', propname='name', displayname='Name',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.htype', propname='htype', displayname='Type',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.value', propname='value', displayname='Value',
             matchingrule=MatchingRule.Loose)
class FileHash(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.mutex', propname='mutex', displayname='Mutex',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.action', propname='action', displayname='Action',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.name', propname='name', displayname='Name',
             matchingrule=MatchingRule.Loose)
class Mutex(ThreatcentralEntity):
    pass


@EntityField(name='ThreatCentral.resourceId', propname='resourceId', displayname='Resource ID',
             matchingrule=MatchingRule.Strict)
@EntityField(name='ThreatCentral.action', propname='action', displayname='Action',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.hive', propname='hive', displayname='Hive',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.key', propname='key', displayname='Key',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.name', propname='name', displayname='Name',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.data', propname='data', displayname='Data',
             matchingrule=MatchingRule.Loose)
@EntityField(name='ThreatCentral.rtype', propname='rtype', displayname='Type',
             matchingrule=MatchingRule.Loose)
class RegistryKey(ThreatcentralEntity):
    pass
