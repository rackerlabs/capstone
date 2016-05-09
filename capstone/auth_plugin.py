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

from capstone import cache
from capstone import conf
from capstone import const


LOG = log.getLogger(__name__)

METHOD_NAME = 'password'


def secure_hash(password):
    # TODO: lol, make secure
    return password


class RackspaceIdentity(object):

    @classmethod
    def from_username(cls, username, password,
                      user_domain_id=None, user_domain_name=None,
                      scope_domain_id=None, scope_project_id=None):
        admin_client = cls.from_admin_config()
        admin_client.authenticate()
        user_ref = admin_client.get_user_by_name(username)
        return cls(username, password,
                   user_domain_id=user_domain_id,
                   user_domain_name=user_domain_name,
                   scope_domain_id=scope_domain_id,
                   scope_project_id=scope_project_id,
                   user_ref=user_ref)

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
        return cls(conf.admin_username, conf.admin_password)

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
        self._token_data = None

    def get_user_url(self, user_id=None):
        user_url = '%s/users' % conf.rackspace_base_url
        if user_id:
            return '%s/%s' % (user_url, user_id)
        return user_url

    def get_token_url(self):
        return conf.rackspace_base_url + '/tokens'

    def _is_in_domain(self, domain, token_data):
        # If the required domain appears in the list of roles (as a project
        # id) then it is safe to assume they are indeed a member of that
        # domain.
        sentinal = object()
        tenants = (role.get('tenantId', sentinal)
                   for role in token_data['access']['user']['roles'])
        if domain in tenants:
            return True  # shortcut for the common case

        user_ref_domain = self._user_ref[const.RACKSPACE_DOMAIN_KEY]
        if not user_ref_domain == domain:
            return False
        return True

    def _assert_user_domain(self, token_data):
        user_domain = self._user_domain_id or self._user_domain_name
        if not self._is_in_domain(user_domain, token_data):
            msg = (_LI('User %(u_name)s does not belong to domain %(d_id)s.') %
                   {'u_name': self._username, 'd_id': user_domain})
            LOG.info(msg)
            raise exception.Unauthorized(msg)
        LOG.info(_LI('User %(u_name)s belongs to domain %(d_id)s.'),
                 {'u_name': self._username, 'd_id': user_domain})

    def _assert_domain_scope(self, token_data):
        if not self._is_in_domain(self._scope_domain_id, token_data):
            msg = (_LI('User %(u_name)s cannot scope to domain %(d_id)s.') %
                   {'u_name': self._username, 'd_id': self._scope_domain_id})
            LOG.info(msg)
            raise exception.Unauthorized(msg)
        LOG.info(_LI('User %(u_name)s can scope to domain %(d_id)s.'),
                 {'u_name': self._username, 'd_id': self._scope_domain_id})

    def _populate_user_domain(self, token_data):
        # Store user's domain since not included in auth response
        token_data['access']['user']['domain_id'] = self._user_ref[
            const.RACKSPACE_DOMAIN_KEY]

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

    def _update_headers_with_x_forwarded_for_header(
            self, headers, context=None):
        if not context:
            return

        if 'x-forwarded-for' not in context.get('header', []):
            headers['X-Forwarded-For'] = context['environment']['REMOTE_ADDR']
        else:
            headers['X-Forwarded-For'] = '{0}, {1}'.format(
                context['header']['x-forwarded-for'],
                context['environment']['REMOTE_ADDR'])

    @cache.memoize_user
    def _get_user(self, url, params=None):
        token = self._token_data['access']['token']['id']
        headers = const.HEADERS.copy()
        headers['X-Auth-Token'] = token

        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code != requests.codes.ok:
            if resp.status_code == requests.codes.not_found:
                msg = resp.json()['itemNotFound']['message']
            else:
                msg = resp.text
            LOG.info(msg)
            raise exception.Unauthorized(msg)
        user = resp.json()['user']
        LOG.info(_LI('Found user %s in v2.'), user['id'])
        return user

    def get_user(self, user_id):
        self.authenticate()
        return self._get_user(self.get_user_url(user_id=user_id))

    def get_user_by_name(self, username):
        self.authenticate()
        return self._get_user(self.get_user_url(), params={'name': username})

    def authenticate(self, context=None):
        if self._token_data:
            return self._token_data

        users_password_hash = secure_hash(self._password)
        if self._user_ref:  # FIXME(dstanek): only needed because of the admin creds
            cached_data = cache.token_region.get(self._user_ref['id'])
            if cached_data:
                cached_password_hash, token_data = cached_data
                if users_password_hash == cached_password_hash:
                    return token_data

        token_data = self._authenticate(self._username)

        if self._user_ref:  # FIXME(dstanek): only needed because of the admin creds
            cache.token_region.set(
                self._user_ref['id'],
                (users_password_hash, token_data))
            cache.token_map_region.set(
                token_data['access']['token']['id'],
                self._user_ref['id'])

        return token_data

    def _authenticate(self, username):
        LOG.info(_LI('Authenticating user %s against v2.'), username)
        headers = const.HEADERS.copy()
        self._update_headers_with_x_forwarded_for_header(headers, context)
        data = {
            "auth": {
                "passwordCredentials": {
                    "username": username,
                    "password": self._password,
                },
            },
        }
        resp = requests.post(
            self.get_token_url(),
            headers=headers,
            json=data)
        resp.raise_for_status()
        token_data = resp.json()

        # Retrieve user to check/populate user's domain
        if not self._user_ref:
            self._user_ref = self.get_user_by_name(username)

        if self._user_domain_id or self._user_domain_name:
            self._assert_user_domain(self._token_data)

        self._populate_user_domain(self._token_data)

        if self._scope_domain_id:
            self._assert_domain_scope(self._token_data)

        if self._scope_project_id:
            self._assert_project_scope(self._token_data)

        LOG.info(_LI('Successfully authenticated user %s against v2.'),
                 username)

        return self._token_data


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
            token_data = identity.authenticate(context)

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise exception.Unauthorized()
            raise

        auth_context['user_id'] = token_data['access']['user']['id']
        auth_context[const.TOKEN_RESPONSE] = token_data
