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

import requests_mock
import testtools

from capstone import cache_invalidator


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestCloudFeedClient(testtools.TestCase):

    def setUp(self):
        super(TestCloudFeedClient, self).setUp()
        self.feed_url = 'http://testfeed.com'
        self.ci = cache_invalidator.CloudFeedClient(self.feed_url)
        filename = os.path.join(FIXTURES_DIR, 'rackspace_feed_response.json')
        with open(filename) as f:
            self.feed_response_body = json.load(f)

    @requests_mock.mock()
    def test_feed_client_parse_correct_number_of_feed_events(self, m):
        m.get(self.feed_url, content=json.dumps(self.feed_response_body))
        entry_list = self.ci.entries
        self.assertEqual(len(entry_list), 3)

    @requests_mock.mock()
    def test_feed_client_set_correct_marker(self, m):
        m.get(self.feed_url, content=json.dumps(self.feed_response_body))
        entries = self.ci.entries
        self.assertEqual(self.ci._marker, entries[0]['id'])

    @requests_mock.Mocker()
    def test_feed_client_reauthentication_on_unauthorized(self, m):
        m.register_uri('GET', self.feed_url,
                       [{'status_code': 401},
                        {'content': json.dumps(self.feed_response_body),
                         'status_code': 200}])
        m.register_uri('POST', requests_mock.ANY, status_code=200,
                       json={"access": {"token": {"id": "1"}}})
        entry_list = self.ci.entries
        self.assertEqual(len(entry_list), 3)

    @requests_mock.mock()
    def test_feed_client_fails_after_single_reauthentication_failure(self, m):
        m.get(self.feed_url, status_code=401)
        m.post(requests_mock.ANY, status_code=200,
               json={"access": {"token": {"id": "1"}}})
        # TODO(jorge_munoz): Attempted to use self.assertRaises, but
        # SystemExit kills process before assertion can be made.
        try:
            self.ci.entries
            assert False
        except SystemExit:
            pass
