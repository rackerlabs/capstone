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
import os

from oslo_config import cfg
from oslo_config import fixture as config_fixture
import requests_mock
import testtools

from capstone import cache_invalidator


CONF = cfg.CONF

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestCloudFeedClient(testtools.TestCase):

    def config_files(self):
        return []

    def config_overrides(self):
        self.config_fixture.config(group='rackspace',
                                   base_url=self.example_url)
        self.config_fixture.config(group='rackspace',
                                   feed_url=self.example_url)
        self.config_fixture.config(group='rackspace',
                                   polling_period=60)
        self.config_fixture.config(group='service_admin',
                                   username='username')
        self.config_fixture.config(group='service_admin',
                                   password='password')

    def config(self, config_files):
        CONF(args=[], project='capstone', default_config_files=config_files)

    @requests_mock.mock()
    def setUp(self, m):
        super(TestCloudFeedClient, self).setUp()
        self.example_url = 'http://example.com'
        self.tokens_url = 'http://example.com/tokens'
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config(self.config_files())
        self.config_overrides()
        m.post(requests_mock.ANY, status_code=200,
               json={"access": {"token": {"id": "id"}}})
        self.ci = cache_invalidator.CloudFeedClient(self.example_url)
        filename = os.path.join(FIXTURES_DIR, 'rackspace_feed_response.json')
        with open(filename) as f:
            self.feed_response_body = json.load(f)

    @requests_mock.mock()
    def test_feed_client_parse_correct_number_of_feed_events(self, m):
        m.get(self.example_url, content=json.dumps(self.feed_response_body))
        self.assertEqual(len(self.ci.entries), 3)

    @requests_mock.mock()
    def test_feed_client_set_correct_marker(self, m):
        m.get(self.example_url, content=json.dumps(self.feed_response_body))
        entries = self.ci.entries
        self.assertEqual(self.ci._marker, entries[0]['id'])

    @requests_mock.Mocker()
    def test_feed_client_reauthentication_on_unauthorized(self, m):
        m.register_uri('GET', self.example_url,
                       [{'status_code': 401},
                        {'content': json.dumps(self.feed_response_body),
                         'status_code': 200}])
        m.register_uri('POST', self.tokens_url, status_code=200,
                       json={"access": {"token": {"id": "id"}}})
        self.assertEqual(len(self.ci.entries), 3)

    @requests_mock.mock()
    def test_feed_client_fails_after_single_reauthentication_failure(self, m):
        # Since assertRaises expects a callable, a method is created to wrap
        # the get entries property of the CloudFeedClient.
        def _get_entries():
            return self.ci.entries

        m.get(self.example_url, status_code=401)
        m.post(self.tokens_url, status_code=200,
               json={"access": {"token": {"id": "id"}}})
        self.assertRaises(RuntimeError, _get_entries)
