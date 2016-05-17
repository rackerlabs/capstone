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

from keystone import exception
import requests_mock
import testtools

from capstone import auth_plugin


class TestV2Outages(testtools.TestCase):

    def setUp(self):
        super(TestV2Outages, self).setUp()
        self.username = uuid.uuid4().hex
        self.user_id = uuid.uuid4().hex
        self.password = uuid.uuid4().hex
        self.domain = uuid.uuid4().hex
        self.token = uuid.uuid4().hex

    @requests_mock.mock()
    def test_v2_get_user_timeout(self, m):
        identity = auth_plugin.RackspaceIdentity.from_username(
            self.username, self.password, user_domain_id=self.domain)
        user_url = identity.url('/users/%s' % self.user_id)

        m.get(user_url, status_code=408)
        m.post(identity.url('/tokens'), status_code=200,
               json={"access": {"token": {"id": "id"}}})

        self.assertRaises(exception.Error,
                          identity.get_user, self.user_id)

    @requests_mock.mock()
    def test_v2_get_user_bad_gateway(self, m):
        identity = auth_plugin.RackspaceIdentity.from_username(
            self.username, self.password, user_domain_id=self.domain)
        user_url = identity.url('/users/%s' % self.user_id)

        m.get(user_url, status_code=502)
        m.post(identity.url('/tokens'), status_code=200,
               json={"access": {"token": {"id": "id"}}})

        self.assertRaises(exception.Error,
                          identity.get_user, self.user_id)

    @requests_mock.mock()
    def test_v2_get_user_by_name_timeout(self, m):
        identity = auth_plugin.RackspaceIdentity.from_username(
            self.username, self.password, user_domain_id=self.domain)

        user_url = identity.url('/users?name=%s' % self.username)
        m.get(user_url, status_code=408)
        m.post(identity.url('/tokens'), status_code=200,
               json={"access": {"token": {"id": "id"}}})
        self.assertRaises(exception.Error,
                          identity.get_user_by_name, self.username)

    @requests_mock.mock()
    def test_v2_authenticate_bad_gateway(self, m):
        identity = auth_plugin.RackspaceIdentity.from_username(
            self.username, self.password, user_domain_id=self.domain)

        m.post(identity.url('/tokens'), status_code=502)
        self.assertRaises(exception.Error, identity.authenticate)
