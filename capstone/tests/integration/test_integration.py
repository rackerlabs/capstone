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
import httplib
import uuid

from os_client_config import config as cloud_config
from oslo_utils import timeutils
import requests
import testtools

from capstone import const
from capstone.tests.integration import schema


class BaseIntegrationTests(testtools.TestCase):

    def setUp(self):
        super(BaseIntegrationTests, self).setUp()

        # Extract credentials so that we can build authentication requests.
        cloud_cfg = cloud_config.OpenStackConfig()

        # Extract authentication information for the Rackspace cloud.
        rackspace_cloud = cloud_cfg.get_one_cloud('rackspace')
        rackspace_args = rackspace_cloud.get_auth_args()

        # Extract authentication information for the Keystone cloud.
        keystone_cloud = cloud_cfg.get_one_cloud('keystone')
        keystone_args = keystone_cloud.get_auth_args()

        # Store common request information that is used to build and make
        # authentication request.
        self.headers = {'Content-Type': 'application/json'}
        self.user_id = rackspace_args['user_id']
        self.username = rackspace_args['username']
        self.password = rackspace_args['password']
        self.project_id = rackspace_args['project_id']
        self.domain_id = rackspace_args['user_domain_id']
        self.rackspace_token_endpoint = (
            rackspace_args['auth_url'].rstrip('/') + '/tokens'
        )
        self.keystone_token_endpoint = (
            keystone_args['auth_url'].rstrip('/') + '/auth/tokens'
        )
        self.keystone_users_endpoint = (
            keystone_args['auth_url'].rstrip('/') + '/users'
        )

    def assertTokenIsUseable(self, token_id):
        """Self validate token against the Rackspace v2.0 API."""
        url = '%s/%s' % (self.rackspace_token_endpoint, token_id)
        headers = self.headers.copy()
        headers['User-Agent'] = 'capstone/0.1'
        headers['X-Auth-Token'] = token_id
        resp = requests.get(url, headers=headers)
        self.assertEqual(httplib.OK, resp.status_code, resp.text)

    def assertValidISO8601ExtendedFormatDatetime(self, dt):
        try:
            return timeutils.parse_strtime(dt, fmt=const.TIME_FORMAT)
        except Exception:
            msg = '%s is not a valid ISO 8601 extended format date time.' % dt
            raise AssertionError(msg)

    def assertValidTokenResponse(self, resp):
        token = resp.json()['token']
        self.assertIsNotNone(token.get('expires_at'))
        expires_at = self.assertValidISO8601ExtendedFormatDatetime(
            token['expires_at'])
        self.assertIsNotNone(token.get('issued_at'))
        issued_at = self.assertValidISO8601ExtendedFormatDatetime(
            token['issued_at'])
        self.assertLess(issued_at, expires_at)
        schema.scoped_validator.validate(token)

    def authenticate(self, auth_data, expected_status=httplib.CREATED):
        resp = requests.post(
            self.keystone_token_endpoint, headers=self.headers, json=auth_data,
            verify='/etc/ssl/certs/keystone.pem',
        )
        self.assertEqual(expected_status, resp.status_code, resp.text)
        return resp

    def list_users(self):
        resp = requests.get(
            self.keystone_users_endpoint, headers=self.headers,
            verify='/etc/ssl/certs/keystone.pem',
        )

        return resp


def generate_password_auth_data(user_data):
    return {
        'auth': {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': user_data,
                },
            },
        },
    }


def generate_password_auth_data_with_scope(user, scope):
    return {
        'auth': {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': user,
                },
            },
            'scope': scope,
        },
    }


def generate_token_auth_data_with_scope(token_id, scope):
    return {
        'auth': {
            'identity': {
                'methods': ['token'],
                'token': {
                    'id': token_id,
                },
            },
            'scope': scope,
        },
    }


class TestGettingADefaultScopedToken(BaseIntegrationTests):

    def test_with_username(self):
        # NOTE(dstanek): legal in capstone, but not in keystone
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_with_username_and_domain_id(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
            'domain': {'id': self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_with_incorrect_username_and_domain_id(self):
        data = generate_password_auth_data({
            'name': uuid.uuid4().hex,
            'password': self.password,
            'domain': {'id': self.domain_id},
        })
        self.authenticate(data, expected_status=httplib.UNAUTHORIZED)

    def test_with_empty_username(self):
        data = generate_password_auth_data({
            'name': '',
            'password': self.password,
            'domain': {'id': self.domain_id},
        })
        self.authenticate(data, expected_status=httplib.BAD_REQUEST)

    def test_with_empty_password(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': '',
            'domain': {'id': self.domain_id},
        })
        self.authenticate(data, expected_status=httplib.BAD_REQUEST)

    def test_with_no_password(self):
        data = generate_password_auth_data({
            'name': self.username,
            'domain': {'id': self.domain_id},
        })
        self.authenticate(data, expected_status=httplib.BAD_REQUEST)

    def test_with_no_username(self):
        data = generate_password_auth_data({
            'password': self.password,
            'domain': {'id': self.domain_id},
        })
        self.authenticate(data, expected_status=httplib.BAD_REQUEST)

    def test_with_no_user(self):
        data = {
            'auth': {
                'identity': {
                    'methods': ['password'],
                    'password': {
                    },
                },
            },
        }
        self.authenticate(data, expected_status=httplib.BAD_REQUEST)

    def test_with_username_and_incorrect_domain_id(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
            'domain': {'id': uuid.uuid4().hex},
        })
        self.authenticate(data, expected_status=httplib.UNAUTHORIZED)

    def test_with_disabled_user(self):
        data = generate_password_auth_data({
            'name': 'disabled',
            'password': self.password,
            'domain': {'id': uuid.uuid4().hex},
        })
        self.authenticate(data, expected_status=httplib.FORBIDDEN)

    def test_with_username_and_domain_name(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
            'domain': {'name': self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_with_username_and_incorrect_domain_name(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
            'domain': {'name': uuid.uuid4().hex},
        })
        self.authenticate(data, expected_status=httplib.UNAUTHORIZED)

    def test_with_user_id(self):
        data = generate_password_auth_data({
            'id': self.user_id,
            'password': self.password,
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_with_incorrect_user_id(self):
        data = generate_password_auth_data({
            'id': uuid.uuid4().hex,
            'password': self.password,
        })
        self.authenticate(data, expected_status=httplib.UNAUTHORIZED)

    def test_with_user_id_and_domain_id(self):
        data = generate_password_auth_data({
            'id': self.user_id,
            'password': self.password,
            'domain': {'id': self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_with_user_id_and_incorrect_domain_id(self):
        data = generate_password_auth_data({
            'id': self.user_id,
            'password': self.password,
            'domain': {'id': uuid.uuid4().hex},
        })
        self.authenticate(data, expected_status=httplib.UNAUTHORIZED)

    def test_with_user_id_and_domain_name(self):
        data = generate_password_auth_data({
            'id': self.user_id,
            'password': self.password,
            'domain': {'name': self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_with_user_id_and_incorrect_domain_name(self):
        data = generate_password_auth_data({
            'id': self.user_id,
            'password': self.password,
            'domain': {'name': uuid.uuid4().hex},
        })
        self.authenticate(data, expected_status=httplib.UNAUTHORIZED)

    def test_with_an_explicitly_unscoped_request(self):
        data = generate_password_auth_data_with_scope(
            user={
                'id': self.user_id,
                'password': self.password,
            },
            scope='unscoped')
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_repeated_authentications_return_the_same_token(self):
        # Tokens should be cached in capstone, so they don't need to be
        # retrieved twice from the v2.0 identity service. This should hold true
        # unless caching in either keystone or capstone is disabled, even
        # though both the mock v2 implementation and the actual v2
        # implementation return unique tokens on each request.
        uncached_user_id = uuid.uuid4().hex
        uncached_password = hashlib.sha1(uncached_user_id).hexdigest()
        data = generate_password_auth_data({
            'id': uncached_user_id,
            'password': uncached_password,
        })

        resp = self.authenticate(data)
        token_1 = resp.headers['X-Subject-Token']

        resp = self.authenticate(data)
        token_2 = resp.headers['X-Subject-Token']

        self.assertEqual(token_1, token_2)


class TestGettingAProjectScopedToken(BaseIntegrationTests):

    def test(self):
        data = generate_password_auth_data_with_scope(
            user={
                'name': self.username,
                'password': self.password,
                'domain': {'id': self.domain_id},
            },
            scope={'project': {'id': self.project_id}})
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_invalid(self):
        data = generate_password_auth_data_with_scope(
            user={
                'name': self.username,
                'password': self.password,
                'domain': {'id': self.domain_id},
            },
            scope={'project': {'id': uuid.uuid4().hex}})
        self.authenticate(data, expected_status=httplib.UNAUTHORIZED)

    def test_with_domain(self):
        data = generate_password_auth_data_with_scope(
            user={
                'name': self.username,
                'password': self.password,
                'domain': {'id': self.domain_id},
            },
            scope={
                'project': {
                    'id': self.project_id,
                    'domain': {'id': self.domain_id},
                }
            })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_with_invalid_domain(self):
        data = generate_password_auth_data_with_scope(
            user={
                'name': self.username,
                'password': self.password,
                'domain': {'id': self.domain_id},
            },
            scope={
                'project': {
                    'id': self.project_id,
                    'domain': {'id': uuid.uuid4().hex},
                }
            })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)


class TestGettingADomainScopedToken(BaseIntegrationTests):

    def test(self):
        data = generate_password_auth_data_with_scope(
            user={
                'name': self.username,
                'password': self.password,
                'domain': {'id': self.domain_id},
            },
            scope={'domain': {'id': self.domain_id}})
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    def test_invalid(self):
        data = generate_password_auth_data_with_scope(
            user={
                'name': self.username,
                'password': self.password,
                'domain': {'id': self.domain_id},
            },
            scope={'domain': {'id': uuid.uuid4().hex}})
        self.authenticate(data, httplib.UNAUTHORIZED)


class TestTokenAuthentication(BaseIntegrationTests):

    def test_with_project_id(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']

        data = generate_token_auth_data_with_scope(
            token_id=token,
            scope={'project': {'id': self.project_id}})
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)
        self.assertValidTokenResponse(resp)

    # NOTE(jorge.munoz): We currently don't support scoping using project name
    def test_with_project_name(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']

        data = generate_token_auth_data_with_scope(
            token_id=token,
            scope={'project': {'name': self.project_id}})
        resp = self.authenticate(data, httplib.BAD_REQUEST)

    def test_with_invalid_project_id(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']

        data = generate_token_auth_data_with_scope(
            token_id=token,
            scope={'project': {'id': 'invalid'}})
        self.authenticate(data, httplib.UNAUTHORIZED)

    def test_with_empty_project_id(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']

        data = generate_token_auth_data_with_scope(
            token_id=token,
            scope={'project': {'id': ''}})
        self.authenticate(data, httplib.BAD_REQUEST)

    def test_with_domain_id(self):
        data = generate_password_auth_data({
            'name': self.username,
            'password': self.password,
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']

        data = generate_token_auth_data_with_scope(
            token_id=token,
            scope={'domain': {'id': self.project_id}})
        resp = self.authenticate(data, httplib.FORBIDDEN)

    def test_with_no_scope(self):
        data = generate_password_auth_data({
            'id': self.username,
            'password': self.password,
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']

        data = {
            'auth': {
                'identity': {
                    'methods': ['token'],
                    'token': {
                        'id': token,
                    },
                },
            },
        }

        self.authenticate(data, httplib.BAD_REQUEST)

    def test_with_empty_token_id(self):
        data = generate_token_auth_data_with_scope(
            token_id='',
            scope={'project': {'id': self.project_id}})
        self.authenticate(data, httplib.BAD_REQUEST)

    def test_with_invalid_token_id(self):
        data = generate_token_auth_data_with_scope(
            token_id='invalid',
            scope={'project': {'id': self.project_id}})
        self.authenticate(data, httplib.UNAUTHORIZED)


class TestCapstonePolicy(BaseIntegrationTests):

    def test_list_users_returns_unauthorized(self):
        data = generate_password_auth_data_with_scope(
            user={
                'name': self.username,
                'password': self.password,
                'domain': {'id': self.domain_id},
            },
            scope={
                'project': {
                    'id': self.project_id,
                    'domain': {'id': uuid.uuid4().hex},
                }
            })
        resp = self.authenticate(data)
        self.headers['X-Auth-Token'] = resp.headers['X-Subject-Token']

        resp = self.list_users()
        self.assertEqual(resp.status_code, 403)
