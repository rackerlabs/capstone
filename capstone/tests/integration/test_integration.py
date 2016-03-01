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

import uuid

import testtools
from testtools import matchers

from os_client_config import config as cloud_config
import requests


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

    def assertTokenIsUseable(self, token_id):
        """Query the Rackspace v2.0 API for the keypairs of the account.

        This method asserts that given a token and a project ID, we can
        retrieve a list of keypairs associated to the project.

        :param token_id: ID of the token to pass in the request

        """
        url = (
            'https://iad.servers.api.rackspacecloud.com/v2/%s/os-keypairs' %
            self.project_id
        )
        headers = self.headers.copy()
        headers['User-Agent'] = 'capstone/0.1'
        headers['X-Auth-Token'] = token_id
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()

    def assertAuthFailed(self, e):
        self.assertThat(e.response.status_code, matchers.Equals(401))
        expected_msg = 'The request you have made requires authentication.'
        self.assertThat(e.response.json()['error']['message'],
            matchers.Equals(expected_msg))

    def authenticate(self, auth_data):
        resp = requests.post(
            self.keystone_token_endpoint, headers=self.headers, json=auth_data)
        resp.raise_for_status()
        return resp


class Tests(BaseIntegrationTests):

    def test_get_v2_token_from_rackspace(self):
        data = {
            "auth": {
                "passwordCredentials": {
                    "username": self.username,
                    "password": self.password,
                },
                "tenantId": self.project_id,
            },
        }
        resp = requests.post(
            self.rackspace_token_endpoint, headers=self.headers, json=data)
        resp.raise_for_status()
        token = resp.json()['access']['token']['id']
        self.assertTokenIsUseable(token)

    def test_get_v3_project_scoped_token_from_keystone(self):
        data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "password": self.password,
                            "domain": {"id": self.project_id},
                        },
                    },
                },
                "scope": {
                    "project": {
                        "name": self.project_id,
                        "domain": {"id": self.project_id},
                    }
                },
            },
        }
        resp = requests.post(
            self.keystone_token_endpoint, headers=self.headers, json=data)
        resp.raise_for_status()
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)

    def test_get_v3_domain_scoped_token_from_keystone(self):
        data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "password": self.password,
                            "domain": {"id": self.project_id},
                        },
                    },
                },
                "scope": {
                    "domain": {"id": self.project_id},
                },
            },
        }
        resp = requests.post(
            self.keystone_token_endpoint, headers=self.headers, json=data)
        resp.raise_for_status()
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)

    def test_get_v3_default_scoped_token_from_keystone_by_user_id(self):
        data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "id": self.user_id,
                            "password": self.password,
                            "domain": {"id": self.domain_id},
                        },
                    },
                },
            },
        }
        resp = requests.post(
            self.keystone_token_endpoint, headers=self.headers, json=data)
        resp.raise_for_status()
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)

    def test_get_v3_domain_scoped_token_from_keystone_using_domain_name(self):
        data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "password": self.password,
                            "domain": {"id": self.project_id},
                        },
                    },
                },
                "scope": {
                    "domain": {"name": self.project_id},
                },
            },
        }
        resp = requests.post(
            self.keystone_token_endpoint, headers=self.headers, json=data)
        resp.raise_for_status()
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)


def generate_password_auth_data(user_data):
    return {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": user_data,
                },
            },
        },
    }

class TestGettingADefaultScopedToken(BaseIntegrationTests):

    def test_with_username(self):
        data = generate_password_auth_data({
            "name": self.username,
            "password": self.password,
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)

    def test_with_username_and_domain_id(self):
        data = generate_password_auth_data({
            "name": self.username,
            "password": self.password,
            "domain": {"id": self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)

    def test_with_username_and_incorrect_domain_id(self):
        data = generate_password_auth_data({
            "name": self.username,
            "password": self.password,
            "domain": {"id": uuid.uuid4().hex},
        })
        e = self.assertRaises(
            requests.exceptions.HTTPError,
            self.authenticate,
            data)
        self.assertAuthFailed(e)

    def test_with_user_id(self):
        data = generate_password_auth_data({
            "id": self.user_id,
            "password": self.password,
            "domain": {"id": self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)

    def test_with_user_id_and_incorrect_domain_id(self):
        data = generate_password_auth_data({
            "id": self.user_id,
            "password": self.password,
            "domain": {"id": uuid.uuid4().hex},
        })
        e = self.assertRaises(
            requests.exceptions.HTTPError,
            self.authenticate,
            data)
        self.assertAuthFailed(e)

    def test_username_and_domain_name(self):
        data = generate_password_auth_data({
            "name": self.username,
            "password": self.password,
            "domain": {"name": self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        self.assertTokenIsUseable(token)

    def test_username_and_incorrect_domain_name(self):
        data = generate_password_auth_data({
            "name": self.username,
            "password": self.password,
            "domain": {"name": uuid.uuid4().hex},
        })
        e = self.assertRaises(
            requests.exceptions.HTTPError,
            self.authenticate,
            data)
        self.assertAuthFailed(e)


class TestValidationIssues(BaseIntegrationTests):

    def test_specifying_user_domain_id_and_name_that_are_different(self):
        pass

    def test_specifying_user_domain_and_project(self):
        pass
