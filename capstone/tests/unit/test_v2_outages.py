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

import json
import uuid

import mock
import requests
from requests import exceptions as req_ex
import testtools

from capstone import auth_plugin
from capstone import exception


class TestV2Outages(testtools.TestCase):

    def setUp(self):
        super(TestV2Outages, self).setUp()
        self.username = uuid.uuid4().hex
        self.user_id = uuid.uuid4().hex
        self.password = uuid.uuid4().hex
        self.domain_id = uuid.uuid4().hex
        self.token = uuid.uuid4().hex

        self.identity = auth_plugin.RackspaceIdentity.from_username(
            self.username, self.password, user_domain_id=self.domain_id)

    def _get_token_data(self):
        return json.dumps({
            "access": {
                "token": {
                    "id": self.token,
                },
                "user": {
                    "name": self.username,
                    "id": self.user_id,
                    "RAX-AUTH:domainId": self.domain_id,
                    "roles": [
                        {
                            "id": "id",
                        },
                    ],
                },
            },
        })

    def _get_user(self):
        return json.dumps({
            "user": {
                "id": self.user_id,
                "username": self.username,
                "RAX-AUTH:domainId": self.domain_id
            }
        })

    @mock.patch('capstone.auth_plugin.requests.get')
    def test_v2_get_user_timeout(self, get_mock):
        get_mock.side_effect = req_ex.Timeout('Timeout')
        self.assertRaises(exception.BadGateway,
                          self.identity.get_user, self.user_id)

    @mock.patch('capstone.auth_plugin.requests.get')
    def test_v2_get_user_by_name_timeout(self, get_mock):
        get_mock.side_effect = req_ex.Timeout('Timeout')
        self.assertRaises(exception.BadGateway,
                          self.identity.get_user_by_name, self.username)

    @mock.patch('capstone.auth_plugin.requests.get')
    def test_v2_get_user_connection_error(self, get_mock):
        get_mock.side_effect = req_ex.ConnectionError('ConnectionError')
        self.assertRaises(exception.BadGateway,
                          self.identity.get_user, self.user_id)

    @mock.patch('capstone.auth_plugin.requests.get')
    def test_v2_get_user_by_name_connection_error(self, get_mock):
        get_mock.side_effect = req_ex.ConnectionError('ConnectionError')
        self.assertRaises(exception.BadGateway,
                          self.identity.get_user, self.user_id)

    @mock.patch('capstone.auth_plugin.requests.post')
    def test_v2_authenticate_connection_error(self, post_mock):
        post_mock.side_effect = req_ex.ConnectionError('ConnectionError')
        self.assertRaises(exception.BadGateway, self.identity.authenticate)

    @mock.patch('capstone.auth_plugin.requests.post')
    @mock.patch('capstone.auth_plugin.requests.get')
    def test_v2_authentication_with_intermittent_failures(self, get_mock,
                                                          post_mock):
        # Valid get user response
        get_resp = requests.models.Response()
        get_resp.status_code = 200
        get_resp._content = self._get_user()
        get_mock.return_value = get_resp

        # Valid authentication response
        post_resp = requests.models.Response()
        post_resp.status_code = 200
        post_resp._content = self._get_token_data()

        # Requests timeout exception
        timoout_ex = req_ex.Timeout('Timeout')
        connection_error_ex = req_ex.ConnectionError('Error')

        post_mock.side_effect = [post_resp, timoout_ex, post_resp,
                                 connection_error_ex]

        self.assertIsNotNone(self.identity.authenticate())
        self.assertRaises(exception.BadGateway, self.identity.authenticate)
        self.assertIsNotNone(self.identity.authenticate())
        self.assertRaises(exception.BadGateway, self.identity.authenticate)
