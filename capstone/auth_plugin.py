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

from capstone import conf
from capstone import const


METHOD_NAME = 'password'


class RackspaceIdentity(object):

    @classmethod
    def from_username(cls, username, password, domain_or_project=None):
        return cls(username, password, domain_or_project)

    @classmethod
    def from_user_id(cls, user_id, password, domain_or_project=None):
        admin_client = cls.from_admin_config()
        admin_client.authenticate()
        username = admin_client.get_user_name(user_id)
        return cls(username, password, domain_or_project)

    @classmethod
    def from_admin_config(cls):
        return cls.from_username(conf.admin_username, conf.admin_password)

    def __init__(self, username, password, domain_or_project):
        self._username = username
        self._password = password
        self._domain_or_project = domain_or_project

    def get_user_url(self, user_id):
        return '%s/users/%s' % (conf.rackspace_base_url, user_id)

    def get_token_url(self):
        return conf.rackspace_base_url + '/tokens/'

    def get_user_name(self, user_id):
        token_data = self.authenticate()
        admin_token = token_data['access']['token']['id']

        headers = const.HEADERS.copy()
        headers['X-Auth-Token'] = admin_token
        resp = requests.get(self.get_user_url(user_id), headers=headers)
        resp.raise_for_status()
        return resp.json()['user']['username']

    def authenticate(self):
        data = {
            "auth": {
                "passwordCredentials": {
                    "username": self._username,
                    "password": self._password,
                },
            },
        }
        resp = requests.post(
            self.get_token_url(),
            headers=const.HEADERS,
            json=data)
        resp.raise_for_status()
        return resp.json()


class Password(auth.AuthMethodHandler):

    def authenticate(self, context, auth_payload, auth_context):
        """Try to authenticate against the identity backend."""
        domain_id = auth_payload['user'].get('domain', {}).get('id')
        project_id = auth_payload['user'].get('project', {}).get('id')
        # TODO(dolph): if (domain_id and project_id), raise a 400
        domain_or_project = domain_id or project_id

        username = auth_payload['user'].get('name')

        try:
            if not username:
                identity = RackspaceIdentity.from_user_id(
                    auth_payload['user']['id'],
                    auth_payload['user']['password'],
                    domain_or_project)
            else:
                identity = RackspaceIdentity.from_username(
                    username,
                    auth_payload['user']['password'],
                    domain_or_project=domain_or_project)
            token_data = identity.authenticate()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise exception.Unauthorized()
            raise

        auth_context['user_id'] = token_data['access']['user']['id']
        auth_context[const.TOKEN_RESPONSE] = token_data
