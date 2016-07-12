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

from keystone import auth
from keystone import exception

from capstone.client import v2
from capstone.common import utils
from capstone import const


class Token(auth.AuthMethodHandler):

    def _validate_scope(self, scope):
        if scope.get('domain', {}).get('id'):
            raise exception.ForbiddenNotSecurity(
                'Token authentication with domain scoped authorization is not '
                'supported by the v3 API.')

        scope_project_id = scope.get('project', {}).get('id')
        scope_project_name = scope.get('project', {}).get('name')
        if not scope_project_id and not scope_project_name:
            raise exception.ValidationError(attribute='project',
                                            target='scope')

        if scope_project_name and 'domain' not in scope['project']:
            raise exception.ValidationError(attribute='domain',
                                            target='project')

    def authenticate(self, context, auth_payload, auth_context):
        if not auth_payload.get('id'):
            raise exception.ValidationError(attribute='id', target='token')

        scope = utils.get_scope(context)
        self._validate_scope(scope)

        scope_project_id = scope.get('project', {}).get('id')
        scope_project_name = scope.get('project', {}).get('name')
        scope_project_domain = scope.get('project', {}).get('domain', {})
        scope_project_domain_id = scope_project_domain.get('id')
        scope_project_domain_name = scope_project_domain.get('name')

        x_forwarded_for = utils.determine_x_forwarded_for_header(context)
        token_id = auth_payload['id']

        identity = v2.RackspaceIdentityToken.from_token(
            token_id,
            scope_project_id=scope_project_id,
            scope_project_name=scope_project_name,
            scope_project_domain_id=scope_project_domain_id,
            scope_project_domain_name=scope_project_domain_name,
            x_forwarded_for=x_forwarded_for)
        token_data = identity.authenticate()
        auth_context['user_id'] = token_data['access']['user']['id']
        auth_context[const.TOKEN_RESPONSE] = token_data
