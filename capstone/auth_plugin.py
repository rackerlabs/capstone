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
import requests

from capstone import conf
from capstone import const


METHOD_NAME = 'password'


class RackspaceIdentity(object):

    def url_for_user(self, user_id):
        return const.USER_URL + user_id

    def get_user_name(self, user_id):
        token_data = self.authenticate(
            conf.admin_username, conf.admin_password, conf.admin_project_id)
        admin_token = token_data['access']['token']['id']

        headers = const.HEADERS.copy()
        headers['X-Auth-Token'] = admin_token
        resp = requests.get(self.url_for_user(user_id), headers=headers)
        resp.raise_for_status()
        return resp.json()['user']['username']

    def authenticate(self, username, password, domain_or_project):
        data = {
            "auth": {
                "passwordCredentials": {
                    "username": username,
                    "password": password,
                },
                "tenantId": domain_or_project,
            },
        }
        resp = requests.post(const.TOKEN_URL, headers=const.HEADERS, json=data)
        resp.raise_for_status()
        return resp.json()


class Password(auth.AuthMethodHandler):

    def authenticate(self, context, auth_payload, auth_context):
        """Try to authenticate against the identity backend."""
        domain_id = auth_payload['user'].get('domain', {}).get('id')
        project_id = auth_payload['user'].get('project', {}).get('id')
        # TODO(dolph): if (domain_id and project_id), raise a 400
        domain_or_project = domain_id or project_id

        identity = RackspaceIdentity()

        username = auth_payload['user'].get('name')
        if 'id' in auth_payload['user'] and not username:
            username = identity.get_user_name(auth_payload['user']['id'])

        token_data = identity.authenticate(username,
                                           auth_payload['user']['password'],
                                           domain_or_project)

        auth_context['user_id'] = token_data['access']['user']['id']
        auth_context[const.TOKEN_RESPONSE] = token_data
