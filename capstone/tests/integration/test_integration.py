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

import testtools

from os_client_config import config as cloud_config
import requests


class IntegrationTests(testtools.TestCase):

    def setUp(self):
        super(IntegrationTests, self).setUp()

        # Extract credentials so that we can build authentication requests.
        cloud_cfg = cloud_config.OpenStackConfig()

        # Extract authentication information for the Rackspace admin cloud.
        rackspace_admin_cloud = cloud_cfg.get_one_cloud('rackspace_admin')
        rackspace_admin_args = rackspace_admin_cloud.get_auth_args()

        # Extract authentication information for the Rackspace cloud.
        rackspace_cloud = cloud_cfg.get_one_cloud('rackspace')
        rackspace_args = rackspace_cloud.get_auth_args()

        # Extract authentication information for the Keystone cloud.
        keystone_cloud = cloud_cfg.get_one_cloud('keystone')
        keystone_args = keystone_cloud.get_auth_args()

        # Store admin request information that is used to make Rackspace's
        # v2.0 admin requests.
        self.admin_username = rackspace_admin_args['username']
        self.admin_password = rackspace_admin_args['password']

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

        # Store admin token
        admin_auth_request = {
            "auth": {
                "passwordCredentials": {
                    "username": self.admin_username,
                    "password": self.admin_password,
                },
            },
        }
        resp = requests.post(
            self.rackspace_token_endpoint,
            headers=self.headers,
            json=admin_auth_request)
        resp.raise_for_status()
        self.admin_token = resp.json()['access']['token']['id']

    def assertTokenIsUseable(self, token_id):
        """Validate token against the Rackspace v2.0 API."""
        url = '%s/%s' % (self.rackspace_token_endpoint, token_id)
        headers = self.headers.copy()
        headers['User-Agent'] = 'capstone/0.1'
        headers['X-Auth-Token'] = self.admin_token
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()

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

    def test_get_v3_default_scoped_token_from_keystone(self):
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
            },
        }
        resp = requests.post(
            self.keystone_token_endpoint, headers=self.headers, json=data)
        resp.raise_for_status()
        token = resp.headers['X-Subject-Token']
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
