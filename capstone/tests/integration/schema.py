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
from keystone.common.validation import validators


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
        'additionalProperties': False,
    }
}

_user_properties = {
    'id': parameter_types.id_string,
    'name': {'type': 'string'},
    'domain': {
        'type': 'object',
        'properties': _domain_properties,
        'required': ['id', 'name'],
        'additionalProperties': False,
    }
}

_role_properties = {
    'id': parameter_types.id_string,
    'name': {'type': 'string'},
}

_endpoint_properties = {
    'id': {'type': 'string'},
    'interface': {'type': 'string'},
    'url': parameter_types.url,
    'region': {'type': ['string', 'null']},
}

_service_properties = {
    'id': {'type': 'string'},
    'type': {'type': 'string'},
    'name': parameter_types.name,
    'endpoints': {
        'type': 'array',
        'items': {
            'type': 'object',
            'properties': _endpoint_properties,
            'required': ['id', 'interface', 'url', 'region'],
            'additionalProperties': False,
        },
        'minItems': 1,
    },
}

_project_scope_properties = {
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
        'properties': _user_properties,
        'required': ['id', 'name', 'domain'],
        'additionalProperties': False,
    },
    'catalog': {
        'type': 'array',
        'items': {
            'type': 'object',
            'properties': _service_properties,
            'required': ['id', 'name', 'type', 'endpoints'],
            'additionalProperties': False,
            'minItems': 1,
        }
    },
    'roles': {
        'type': 'array',
        'items': {
            'type': 'object',
            'properties': _role_properties,
            'required': ['id', 'name'],
        },
        'minItems': 1,
    },
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
    'properties': _project_scope_properties,
    'required': ['audit_ids', 'expires_at', 'issued_at', 'methods',
                 'user', 'project', 'catalog'],
    'optional': ['is_domain'],
    'additionalProperties': False,
}

# Validator objects
scoped_validator = validators.SchemaValidator(schema)
