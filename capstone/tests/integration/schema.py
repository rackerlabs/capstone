# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common.validation import parameter_types

_domain_properties = {
    'id': parameter_types.id_string,
    'name': {'type': 'string'}
}

_project_properties = {
    'id': parameter_types.id_string,
    'name': {'type': 'string'},
    'domain': {
        'type': 'object',
        'properties': _domain_properties,
        'required': ['id', 'name'],
        'additonalProperties': False,
    }
}

_user_properties = {
    'id': parameter_types.id_string,
    'name': {'type': 'string'},
    'domain': {
        'type': 'object',
        'properties': _domain_properties,
        'required': ['id', 'name'],
        'additonalProperties': False,
    }
}

project_scope_properties = {
    'audit_ids': {
        'type': 'array',
        'items': {
            'type': 'string',
        },
        'minItems': 1,
        'maxItems': 2,
    },
    'expires_at': {'type': 'string'},
    'issued_at': {'type': 'string'},
    'methods': {
        'type': 'array',
        'items': {
            'type': 'string',
        },
    },
    'user': {
        'type': 'object',
        'required': ['id', 'name', 'domain'],
        'properties': _user_properties,
        'additionalProperties': False,
    },
    'catalog': {'type': 'array'},
    'roles': {'type': 'array'},
    'project': {
        'type': ['object'],
        'required': ['id', 'name', 'domain'],
        'properties': _project_properties,
        'additionalProperties': False,
    },
    'is_domain': parameter_types.boolean,
}

schema = {
    'type': 'object',
    'properties': project_scope_properties,
    'required': ['audit_ids', 'expires_at', 'issued_at', 'methods',
                 'user', 'project', 'catalog'],
    'optional': ['bind', 'is_domain'],
    'additionalProperties': False,
}
