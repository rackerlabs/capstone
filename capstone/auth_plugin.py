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
from keystone.i18n import _LI
from oslo_log import log
import requests

from capstone import conf
from capstone import const


LOG = log.getLogger(__name__)

METHOD_NAME = 'password'


class RackspaceIdentity(object):

    @classmethod
    def from_username(cls, username, password,
                      user_domain_id=None, user_domain_name=None,
                      scope_domain_id=None, scope_project_id=None):
        return cls(username, password,
                   user_domain_id=user_domain_id,
                   user_domain_name=user_domain_name,
                   scope_domain_id=scope_domain_id,
                   scope_project_id=scope_project_id)

    @classmethod
    def from_user_id(cls, user_id, password,
                     user_domain_id=None, user_domain_name=None,
                     scope_domain_id=None, scope_project_id=None):
        admin_client = cls.from_admin_config()
        admin_client.authenticate()
        user_ref = admin_client.get_user(user_id)
        username = user_ref['username']
        return cls(username, password,
                   user_domain_id=user_domain_id,
                   user_domain_name=user_domain_name,
                   scope_domain_id=scope_domain_id,
                   scope_project_id=scope_project_id,
                   user_ref=user_ref)

    @classmethod
    def from_admin_config(cls):
        return cls.from_username(conf.admin_username, conf.admin_password)

    def __init__(self, username, password,
                 user_domain_id=None, user_domain_name=None,
                 scope_domain_id=None, scope_project_id=None,
                 user_ref=None):
        self._username = username
        self._password = password
        self._user_domain_id = user_domain_id
        self._user_domain_name = user_domain_name
        self._scope_domain_id = scope_domain_id
        self._scope_project_id = scope_project_id
        self._user_ref = user_ref

    def get_user_url(self, user_id):
        return '%s/users/%s' % (conf.rackspace_base_url, user_id)

    def get_token_url(self):
        return conf.rackspace_base_url + '/tokens/'

    def _assert_user_domain(self, user_id):
        user_domain = self._user_domain_id or self._user_domain_name
        admin_client = RackspaceIdentity.from_admin_config()
        admin_client.authenticate()
        if not self._user_ref:
            self._user_ref = admin_client.get_user(user_id)

        user_ref_domain = self._user_ref[const.RACKSPACE_DOMAIN_KEY]
        if not user_ref_domain == user_domain:
            msg = (_LI('User %(u_name)s does not belong to domain %(d_id)s.') %
                   {'u_name': self._username, 'd_id': user_domain})
            LOG.info(msg)
            raise exception.Unauthorized(msg)
        LOG.info(_LI('User %(u_name)s belongs to domain %(d_id)s.'),
                 {'u_name': self._username, 'd_id': user_domain})

    def _assert_domain_scope(self, user_id):
        # TODO(dstanek): if this will be truly the same as
        # _assert_user_domain then i'll combine the two as _assert_domain
        admin_client = RackspaceIdentity.from_admin_config()
        admin_client.authenticate()
        if not self._user_ref:
            self._user_ref = admin_client.get_user(user_id)

        user_domain = self._user_ref[const.RACKSPACE_DOMAIN_KEY]
        if not user_domain == self._scope_domain_id:
            msg = (_LI('User %(u_name)s cannot scope to domain %(d_id)s.') %
                   {'u_name': self._username, 'd_id': self._scope_domain_id})
            LOG.info(msg)
            raise exception.Unauthorized(msg)
        LOG.info(_LI('User %(u_name)s can scope to domain %(d_id)s.'),
                 {'u_name': self._username, 'd_id': self._scope_domain_id})

    def _assert_project_scope(self, token_data):
        sentinal = object()
        tenants = (role.get('tenantId', sentinal)
                   for role in token_data['access']['user']['roles'])
        if self._scope_project_id not in tenants:
            msg = (_LI('User %(u_name)s cannot scope to project %(p_id)s.') %
                   {'u_name': self._username, 'p_id': self._scope_project_id})
            LOG.info(msg)
            raise exception.Unauthorized(msg)
        LOG.info(_LI('User %(u_name)s can scope to project %(p_id)s.'),
                 {'u_name': self._username, 'p_id': self._scope_project_id})

    def get_user(self, user_id):
        token_data = self.authenticate()
        admin_token = token_data['access']['token']['id']

        headers = const.HEADERS.copy()
        headers['X-Auth-Token'] = admin_token
        resp = requests.get(self.get_user_url(user_id), headers=headers)
        if resp.status_code != requests.codes.ok:
            if resp.status_code == requests.codes.not_found:
                msg = resp.json()['itemNotFound']['message']
            else:
                msg = resp.text
            LOG.info(msg)
            raise exception.Unauthorized(msg)
        LOG.info(_LI('Found user %s in Rackspace\'s Identity system.'),
                 user_id)
        return resp.json()['user']

    def authenticate(self):
        LOG.info(_LI('Authenticating user %s against Rackspace\'s Identity '
                     'system.'), self._username)
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
        token_data = resp.json()

        if self._user_domain_id or self._user_domain_name:
            self._assert_user_domain(token_data['access']['user']['id'])

        if self._scope_domain_id:
            self._assert_domain_scope(token_data['access']['user']['id'])

        if self._scope_project_id:
            self._assert_project_scope(token_data)

        LOG.info(_LI('Successfully authenticated user %s against Rackspace\'s '
                     'Identity system.'), self._username)
        return token_data


class Password(auth.AuthMethodHandler):

    def _get_scope(self, context):
        auth_params = context['environment']['openstack.params']['auth']
        return auth_params.get('scope', {})

    def authenticate(self, context, auth_payload, auth_context):
        """Try to authenticate against the identity backend."""
        user_domain_id = auth_payload['user'].get('domain', {}).get('id')
        user_domain_name = auth_payload['user'].get('domain', {}).get('name')

        scope = self._get_scope(context)
        scope_domain_id = scope.get('domain', {}).get('id')
        scope_project_id = scope.get('project', {}).get('id')
        # TODO(dolph): if (domain_id and project_id), raise a 400

        username = auth_payload['user'].get('name')

        try:
            if not username:
                identity = RackspaceIdentity.from_user_id(
                    auth_payload['user']['id'],
                    auth_payload['user']['password'],
                    user_domain_id=user_domain_id,
                    user_domain_name=user_domain_name,
                    scope_domain_id=scope_domain_id,
                    scope_project_id=scope_project_id)
            else:
                identity = RackspaceIdentity.from_username(
                    username,
                    auth_payload['user']['password'],
                    user_domain_id=user_domain_id,
                    user_domain_name=user_domain_name,
                    scope_domain_id=scope_domain_id,
                    scope_project_id=scope_project_id)
            token_data = identity.authenticate()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise exception.Unauthorized()
            raise

        auth_context['user_id'] = token_data['access']['user']['id']
        auth_context[const.TOKEN_RESPONSE] = token_data
