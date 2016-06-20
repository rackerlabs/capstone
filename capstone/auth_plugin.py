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
import requests

from capstone.client import v2
from capstone import const


class Password(auth.AuthMethodHandler):

    def _get_scope(self, context):
        auth_params = context['environment']['openstack.params']['auth']
        scope = auth_params.get('scope', {})

        # NOTE(dstanek): support requests that are specifically unscoped
        if scope == 'unscoped':
            return {}

        return scope

    def _validate_auth_data(self, auth_payload):
        """Validate authentication payload."""
        if 'user' not in auth_payload:
            raise exception.ValidationError(attribute='user', target='auth')
        user_info = auth_payload['user']
        user_id = user_info.get('id')
        user_name = user_info.get('name')
        user_password = user_info.get('password')
        if not user_id and not user_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='user')
        if not user_password:
            raise exception.ValidationError(attribute='password',
                                            target='user')

    def authenticate(self, context, auth_payload, auth_context):
        """Try to authenticate against the identity backend."""
        self._validate_auth_data(auth_payload)

        user_domain_id = auth_payload['user'].get('domain', {}).get('id')
        user_domain_name = auth_payload['user'].get('domain', {}).get('name')

        scope = self._get_scope(context)
        scope_domain_id = scope.get('domain', {}).get('id')
        scope_project_id = scope.get('project', {}).get('id')
        # TODO(dolph): if (domain_id and project_id), raise a 400

        username = auth_payload['user'].get('name')

        x_forwarded_for = self._determine_x_forwarded_for_header(context)
        try:
            if not username:
                identity = v2.RackspaceIdentity.from_user_id(
                    auth_payload['user']['id'],
                    auth_payload['user']['password'],
                    user_domain_id=user_domain_id,
                    user_domain_name=user_domain_name,
                    scope_domain_id=scope_domain_id,
                    scope_project_id=scope_project_id,
                    x_forwarded_for=x_forwarded_for)
            else:
                identity = v2.RackspaceIdentity.from_username(
                    username,
                    auth_payload['user']['password'],
                    user_domain_id=user_domain_id,
                    user_domain_name=user_domain_name,
                    scope_domain_id=scope_domain_id,
                    scope_project_id=scope_project_id,
                    x_forwarded_for=x_forwarded_for)
            token_data = identity.authenticate()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise exception.Unauthorized()
            raise

        auth_context['user_id'] = token_data['access']['user']['id']
        auth_context[const.TOKEN_RESPONSE] = token_data

    def _determine_x_forwarded_for_header(self, context):
        if not context:
            return

        if 'x-forwarded-for' not in context.get('header', []):
            return context['environment']['REMOTE_ADDR']
        else:
            return '{0}, {1}'.format(
                context['header']['x-forwarded-for'],
                context['environment']['REMOTE_ADDR'])
