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

import hashlib

from keystone.common import utils
from keystone import exception
from keystone.i18n import _LI
from oslo_log import log
import requests

from capstone import cache
from capstone import conf
from capstone import const
from capstone import exception as capstone_exception


LOG = log.getLogger(__name__)


class RackspaceIdentity(object):

    @classmethod
    def from_username(cls, username, password,
                      user_domain_id=None, user_domain_name=None,
                      scope_domain_id=None, scope_project_id=None,
                      x_forwarded_for=None):
        admin_client = RackspaceIdentityAdmin.from_config()
        admin_client.authenticate()
        try:
            user_ref = admin_client.get_user_by_name(username)
        except exception.NotFound as e:
            raise exception.Unauthorized(e)
        return cls(username, password, user_ref,
                   user_domain_id=user_domain_id,
                   user_domain_name=user_domain_name,
                   scope_domain_id=scope_domain_id,
                   scope_project_id=scope_project_id,
                   x_forwarded_for=x_forwarded_for)

    @classmethod
    def from_user_id(cls, user_id, password,
                     user_domain_id=None, user_domain_name=None,
                     scope_domain_id=None, scope_project_id=None,
                     x_forwarded_for=None):
        admin_client = RackspaceIdentityAdmin.from_config()
        admin_client.authenticate()
        try:
            user_ref = admin_client.get_user(user_id)
        except exception.NotFound as e:
            raise exception.Unauthorized(e)
        username = user_ref['username']
        return cls(username, password, user_ref,
                   user_domain_id=user_domain_id,
                   user_domain_name=user_domain_name,
                   scope_domain_id=scope_domain_id,
                   scope_project_id=scope_project_id,
                   x_forwarded_for=x_forwarded_for)

    def __init__(self, username, password, user_ref,
                 user_domain_id=None, user_domain_name=None,
                 scope_domain_id=None, scope_project_id=None,
                 x_forwarded_for=None):
        self._username = username
        self._password = password
        self._user_ref = user_ref
        self._user_domain_id = user_domain_id
        self._user_domain_name = user_domain_name
        self._scope_domain_id = scope_domain_id
        self._scope_project_id = scope_project_id
        self._x_forwarded_for = x_forwarded_for
        self._token_data = None

    def url(self, path):
        """Return a complete URL given just a path."""
        return '%s%s' % (conf.rackspace_base_url, path)

    def GET(self, path, params=None, auth_token=None):
        """GET the resource at the specified path.

        The specified path is expected to begin with a slash (/).

        """
        url = self.url(path)
        LOG.info('GET %s', url)
        headers = {
            'Accept': 'application/json'}
        if auth_token:
            headers['X-Auth-Token'] = auth_token

        try:
            resp = requests.get(url, headers=headers, params=params,
                                timeout=conf.request_timeout)
        except requests.exceptions.RequestException as e:
            LOG.info(e)
            raise capstone_exception.BadGateway()

        if resp.status_code == requests.codes.ok:
            return resp.json()

        self.handle_unexpected_response(resp)

    def POST(self, path, data, headers=None,
             expected_status=requests.codes.created):
        """POST data to the specified path.

        The specified path is expected to begin with a slash (/).

        """
        url = self.url(path)
        LOG.info('POST %s', url)
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

        try:
            resp = requests.post(url, headers=headers, json=data,
                                 timeout=conf.request_timeout)
        except requests.exceptions.RequestException as e:
            LOG.info(e)
            raise capstone_exception.BadGateway()

        if resp.status_code == expected_status:
            return resp.json()

        self.handle_unexpected_response(resp)

    def handle_unexpected_response(self, resp):
        if resp.status_code == requests.codes.not_found:
            msg = resp.json()['itemNotFound']['message']
            LOG.info(msg)
            raise exception.NotFound(msg)
        elif resp.status_code == requests.codes.unauthorized:
            msg = resp.json()['unauthorized']['message']
            LOG.info(msg)
            raise exception.Unauthorized(msg)
        elif resp.status_code == requests.codes.bad_request:
            msg = resp.json()['badRequest']['message']
            LOG.info(msg)
            raise exception.ValidationError(msg)
        elif resp.status_code == requests.codes.forbidden:
            body = resp.json()
            # User/domain disabled cases
            if 'userDisabled' in body:
                msg = body['userDisabled']['message']
            else:
                msg = body['forbidden']['message']
            LOG.info(msg)
            raise exception.ForbiddenNotSecurity(msg)

        LOG.info(resp.text)
        raise exception.UnexpectedError(resp.text)

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

    @cache.memoize_user
    def _get_user(self, path, params):
        token = self._token_data['access']['token']['id']
        return self.GET(path, params=params, auth_token=token)['user']

    def get_user(self, user_id):
        self.authenticate()
        params = None
        return self._get_user('/users/%s' % user_id, params)

    def get_user_by_name(self, username):
        self.authenticate()
        return self._get_user('/users', {'name': username})

    @cache.memoize_token
    def validate_token(self, token_id):
        self.authenticate()
        token = self._token_data['access']['token']['id']
        return self.GET('/tokens/%s' % token_id, params=None, auth_token=token)

    def _authenticate(self):
        cached_data = cache.token_region.get(self._user_ref['id'])
        if cached_data:
            cached_password_hash, token_data = cached_data
            if utils.check_password(self._password, cached_password_hash):
                return token_data

        headers = const.HEADERS.copy()
        if self._x_forwarded_for:
            headers['X-Forwarded-For'] = self._x_forwarded_for

        LOG.info(_LI('Authenticating user %s against v2.'), self._username)
        token_data = self.POST(
            '/tokens',
            headers=headers,
            data={
                'auth': {
                    'passwordCredentials': {
                        'username': self._username,
                        'password': self._password,
                    },
                },
            },
            expected_status=requests.codes.ok
        )

        users_password_hash = utils.hash_password(self._password)
        cache.token_region.set(
            self._user_ref['id'],
            (users_password_hash, token_data))
        cache.token_map_region.set(
            token_data['access']['token']['id'],
            self._user_ref['id'])
        return token_data

    def authenticate(self):
        if self._token_data:
            return self._token_data

        self._token_data = self._authenticate()

        if self._user_domain_id or self._user_domain_name:
            self._assert_user_domain(self._token_data)

        self._populate_user_domain(self._token_data)

        if self._scope_domain_id:
            self._assert_domain_scope(self._token_data)

        if self._scope_project_id:
            self._assert_project_scope(self._token_data)

        LOG.info(_LI('Successfully authenticated user %s against v2.'),
                 self._username)

        return self._token_data


class RackspaceIdentityToken(RackspaceIdentity):

    def __init__(self, token_id, scope_project_id, user_ref,
                 x_forwarded_for=None):
        super(RackspaceIdentityToken, self).__init__(token_id,
                                                     scope_project_id,
                                                     user_ref,
                                                     x_forwarded_for=None)
        self._token_id = token_id
        self._scope_project_id = scope_project_id
        self._user_ref = user_ref
        self._x_forwarded_for = x_forwarded_for
        self._token_data = None

    @classmethod
    def from_token(cls, token_id, scope_project_id,
                   user_ref=None, x_forwarded_for=None):
        admin_client = RackspaceIdentityAdmin.from_config()
        admin_client.authenticate()
        token_data = admin_client.validate_token(token_id)
        user_id = token_data['access']['user']['id']
        user_ref = admin_client.get_user(user_id)
        return cls(token_id, scope_project_id,
                   user_ref=user_ref,
                   x_forwarded_for=x_forwarded_for)

    def _token_authenticate(self):
        hash_token = hashlib.sha1(self._token_id).hexdigest()
        cached_data = cache.token_region.get(hash_token)
        if cached_data:
            return cached_data

        headers = const.HEADERS.copy()
        if self._x_forwarded_for:
            headers['X-Forwarded-For'] = self._x_forwarded_for

        LOG.info(_LI('Token authentication against v2.'))
        token_data = self.POST(
            '/tokens',
            headers=headers,
            data={
                'auth': {
                    'token': {
                        'id': self._token_id,
                    },
                    'tenantId': self._scope_project_id,
                },
            },
            expected_status=requests.codes.ok
        )

        cache.token_region.set(hash_token, token_data)
        return token_data

    def authenticate(self):
        if self._token_data:
            return self._token_data

        self._token_data = self._token_authenticate()
        self._populate_user_domain(self._token_data)
        self._assert_project_scope(self._token_data)

        LOG.info(_LI('Successfully authenticated token SHA1{%s} against v2.'),
                 hashlib.sha1(self._token_id).hexdigest())
        return self._token_data


class RackspaceIdentityAdmin(RackspaceIdentity):

    @classmethod
    def from_config(cls):
        return cls(conf.admin_username, conf.admin_password,
                   {'id': conf.admin_user_id})

    def authenticate(self):
        if self._token_data:
            return self._token_data

        self._token_data = self._authenticate()
        return self._token_data
