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

import unittest

from os_client_config import config as cloud_config
import requests


class IntegrationTests(unittest.TestCase):

    def setUp(self):
        # extract credentials so that we can build authentication requests.
        cloud_cfg = cloud_config.OpenStackConfig()

        # Extract authentication information for the Rackspace cloud.
        rax_cloud = cloud_cfg.get_one_cloud('rax')
        self.rax_args = rax_cloud.get_auth_args()

        # Extract authentication information for the Keystone cloud.
        keystone_cloud = cloud_cfg.get_one_cloud('keystone')
        self.keystone_args = keystone_cloud.get_auth_args()

        # Store common request information that is used to build and make
        # authentication request.
        self.headers = {'Content-Type': 'application/json'}
        self.username = self.rax_args['username']
        self.password = self.rax_args['password']
        self.project_id = self.rax_args['project_id']
        self.rax_token_endpoint = (
            self.rax_args['auth_url'].rstrip('/') + '/tokens'
        )
        self.keystone_token_endpoint = (
            self.keystone_args['auth_url'].rstrip('/') + '/auth/tokens'
        )

    def get_v2_token_from_rackspace(self):
        """Build an authentication request for Rackspace v2.0 and get token.

        :returns: a token from v2.0 in the form of a string

        """
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
            self.rax_token_endpoint, headers=self.headers, json=data)
        resp.raise_for_status()
        return resp.json()['access']['token']['id']

    def get_v3_default_scoped_token_from_keystone(self):
        """Build an authentication request for Keystone v3 and get a token.

        :returns: a token from v3 in the form of a string

        """
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
        return resp.headers['X-Subject-Token']

    def get_v3_project_scoped_token_from_keystone(self):
        """Build an authentication request for Keystone v3 and get a token.

        The authentication request being built is asking for a project-scoped
        token.

        :returns: a project-scoped token from v3 in the form of a string

        """
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
        return resp.headers['X-Subject-Token']

    def get_v3_domain_scoped_token_from_keystone(self):
        """Build an authentication request for Keystone v3 and get a token.

        The authentication request being built is asking for a domain-scoped
        token.

        :returns: a project-scoped token from v3 in the form of a string

        """
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
        return resp.headers['X-Subject-Token']

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

    def test_integration(self):

        # Get a token from the v2.0 Rackspace API.
        token = self.get_v2_token_from_rackspace()
        self.assertTokenIsUseable(token)

        # Get a token from v3 Keystone API.
        token = self.get_v3_default_scoped_token_from_keystone()
        self.assertTokenIsUseable(token)

        # Request a project-scoped token from the v3 Keystone API.
        token = self.get_v3_project_scoped_token_from_keystone()
        self.assertTokenIsUseable(token)

        # Request a domain-scoped token from the v3 Keystone API.
        token = self.get_v3_domain_scoped_token_from_keystone()
        self.assertTokenIsUseable(token)
