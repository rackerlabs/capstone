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
    def from_username(cls, username, password,
                      user_domain_id=None, user_project_id=None):

        return cls(username, password, user_domain_id, user_project_id)

    @classmethod
    def from_user_id(cls, user_id, password,
                     user_domain_id=None, user_project_id=None):

        admin_client = cls.from_admin_config()
        admin_client.authenticate()
        user_ref = admin_client.get_user(user_id)
        username = user_ref['username']
        return cls(username, password, user_domain_id, user_project_id,
                   user_ref=user_ref)

    @classmethod
    def from_admin_config(cls):
        return cls.from_username(conf.admin_username, conf.admin_password)

    def __init__(self, username, password, user_domain_id, user_project_id,
                 user_ref=None):
        self._username = username
        self._password = password
        self._user_domain_id = user_domain_id
        self._user_project_id = user_project_id
        self._user_ref = user_ref
        self._token = None

    def _assert_user_domain(self, user_id):
        if not self._user_ref:
            admin_client = RackspaceIdentity.from_admin_config()
            admin_client.authenticate()
            self._user_ref = admin_client.get_user(user_id)

        key = const.RACKSPACE_DOMAIN_KEY
        if not self._user_ref[key] == self._user_domain_id:
            raise exception.Unauthorized()

    def authenticate(self):
        data = {
            "auth": {
                "passwordCredentials": {
                    "username": self._username,
                    "password": self._password,
                },
            },
        }
        url = self.get_token_url()
        resp = requests.post(url, headers=const.HEADERS, json=data)
        resp.raise_for_status()
        token_data = resp.json()

        if self._user_domain_id:
            self._assert_user_domain(token_data['access']['user']['id'])

        self._token = token_data['access']['token']['id']
        return token_data

    def get_user_url(self, user_id):
        return '%s/users/%s' % (conf.rackspace_base_url, user_id)

    def get_token_url(self):
        return conf.rackspace_base_url + '/tokens/'

    def get_user(self, user_id):
        headers = const.HEADERS.copy()
        headers['X-Auth-Token'] = self._token
        resp = requests.get(self.get_user_url(user_id), headers=headers)
        resp.raise_for_status()
        return resp.json()['user']


class Password(auth.AuthMethodHandler):

    def authenticate(self, context, auth_payload, auth_context):
        """Try to authenticate against the identity backend."""
        user_domain_id = auth_payload['user'].get('domain', {}).get('id')
        if not user_domain_id:
            user_domain_id = auth_payload['user'].get('domain', {}).get('name')
        user_project_id = auth_payload['user'].get('project', {}).get('id')
        # TODO(dolph): if (user_domain_id and user_project_id), raise a 400

        username = auth_payload['user'].get('name')
        try:
            if not username:
                # TODO(dstanek): assert user_domain_id!!
                identity = RackspaceIdentity.from_user_id(
                    auth_payload['user']['id'],
                    auth_payload['user']['password'],
                    user_domain_id,
                    user_project_id=user_project_id)
            else:
                identity = RackspaceIdentity.from_username(
                    username,
                    auth_payload['user']['password'],
                    user_domain_id=user_domain_id,
                    user_project_id=user_project_id)
            token_data = identity.authenticate()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise exception.Unauthorized()
            raise

        user_id = token_data['access']['user']['id']

        auth_context['user_id'] = user_id
        auth_context[const.TOKEN_RESPONSE] = token_data
