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
from capstone import exception as capstone_exception


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
        try:
            user_ref = admin_client.get_user(user_id)
        except exception.NotFound as e:
            raise exception.Unauthorized(e)
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

        self.auth_token = None

    def url(self, path):
        """Return a complete URL given just a path."""
        return '%s%s' % (conf.rackspace_base_url, path)

    def GET(self, path, params=None, auth_token=None):
        """GET the resource at the specified path.

        The specified path is expected to begin with a slash (/).

        """
        url = self.url(path)
        LOG.info('GET %s' % url)
        headers = {
            'X-Auth-Token': self.auth_token,
            'Accept': 'application/json'}

        try:
            resp = requests.get(url, headers=headers, params=params,
                                timeout=conf.request_timeout)
        except requests.exceptions.RequestException as e:
            LOG.info(e.message)
            raise capstone_exception.BadGateway(e.message)

        if resp.status_code == requests.codes.ok:
            return resp.json()

        self.handle_unexpected_response(resp)

    def POST(self, path, data, expected_status=requests.codes.created):
        """POST data to the specified path.

        The specified path is expected to begin with a slash (/).

        """
        url = self.url(path)
        LOG.info('POST %s')
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

        try:
            resp = requests.post(url, headers=headers, json=data,
                                 timeout=conf.request_timeout)
        except requests.exceptions.RequestException as e:
            LOG.info(e.message)
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

    def get_user(self, user_id):
        user = self.GET('/users/%s' % user_id)['user']
        LOG.info(_LI('Found user %s in v2.'), user['username'])
        return user

    def get_user_by_name(self, username):
        user = self.GET('/users', params={'name': username})['user']
        LOG.info(_LI('Found user %s in v2.'), user['username'])
        return user

    def authenticate(self, context=None):
        headers = const.HEADERS.copy()
        self._update_headers_with_x_forwarded_for_header(headers, context)

        LOG.info(_LI('Authenticating user %s against v2.'), self._username)

        token_data = self.POST(
            '/tokens',
            data={
                "auth": {
                    "passwordCredentials": {
                        "username": self._username,
                        "password": self._password,
                    },
                },
            },
            expected_status=requests.codes.ok
        )
        self.auth_token = token_data['access']['token']['id']

        # Retrieve user to check/populate user's domain
        if not self._user_ref:
            self._user_ref = self.get_user_by_name(self._username)

        if self._user_domain_id or self._user_domain_name:
            self._assert_user_domain(token_data)

        self._populate_user_domain(token_data)

        if self._scope_domain_id:
            self._assert_domain_scope(token_data)

        if self._scope_project_id:
            self._assert_project_scope(token_data)

        LOG.info(_LI('Successfully authenticated user %s against v2.'),
                 self._username)
        return token_data


class Password(auth.AuthMethodHandler):

    def _get_scope(self, context):
        auth_params = context['environment']['openstack.params']['auth']
        return auth_params.get('scope', {})

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
