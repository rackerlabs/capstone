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

import os

from keystone import auth
import requests
from six.moves import configparser

from capstone import const


METHOD_NAME = 'password'


class Password(auth.AuthMethodHandler):

    def __init__(self, *args, **kwargs):
        super(Password, self).__init__(*args, **kwargs)
        config = configparser.ConfigParser()
        config.read(['/etc/capstone/capstone.conf',
                     os.environ.get('CAPSTONE_CONFIG', '')])
        self._admin_username = config.get('service_admin', 'username')
        self._admin_password = config.get('service_admin', 'password')
        self._admin_project_id = config.get('service_admin', 'project_id')

    def get_user_name(self, user_id):
        data = {
            "auth": {
                "passwordCredentials": {
                    "username": self._admin_username,
                    "password": self._admin_password,
                },
                "tenantId": self._admin_project_id,
            },
        }
        resp = requests.post(const.TOKEN_URL, headers=const.HEADERS, json=data)
        resp.raise_for_status()
        admin_token = resp.json()['access']['token']['id']

        user_url = (
            'https://identity.api.rackspacecloud.com/v2.0/users/%s' % user_id
        )
        headers = const.HEADERS.copy()
        headers['X-Auth-Token'] = admin_token
        resp = requests.get(user_url, headers=headers)
        resp.raise_for_status()
        return resp.json()['user']['username']

    def authenticate(self, context, auth_payload, auth_context):
        """Try to authenticate against the identity backend."""
        domain_or_project = auth_payload['user'].get('domain', {}).get('id')
        if not domain_or_project:
            domain_or_project = (auth_payload['user']
                                 .get('project', {})
                                 .get('id'))

        username = auth_payload['user'].get('name')
        if 'id' in auth_payload['user'] and not username:
            username = self.get_user_name(auth_payload['user']['id'])

        data = {
            "auth": {
                "passwordCredentials": {
                    "username": username,
                    "password": auth_payload['user']['password'],
                },
                "tenantId": domain_or_project,
            },
        }
        resp = requests.post(const.TOKEN_URL, headers=const.HEADERS, json=data)
        resp.raise_for_status()

        json_data = resp.json()
        auth_context['user_id'] = json_data['access']['user']['id']
        auth_context['rax:token_response'] = json_data
