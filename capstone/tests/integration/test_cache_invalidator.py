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

from keystone.common import config
import mock
from oslo_config import cfg
import requests

# TODO(jorge.munoz): Fix cache_invalidator import
CONF = cfg.CONF
config.configure()

config.set_config_defaults()
keystone_conf = os.environ.get('KEYSTONE_CONFIG',
                               '/etc/keystone/keystone.conf')
CONF(args=[], default_config_files=[keystone_conf])

from capstone import cache_invalidator
from capstone.tests.integration import test_integration


class TestCacheInvalidator(test_integration.BaseIntegrationTests):

    def setUp(self):
        super(TestCacheInvalidator, self).setUp()
        self.example_url = 'http://example.com'
        self.client = cache_invalidator.CloudFeedClient(self.example_url)

    def _build_feed(self):
        return {
            "feed": {
                "@type": "http://www.w3.org/2005/Atom",
                "entry": [
                ]
            }
        }

    def _get_delete_token_event(self, token_id):
        feed = self._build_feed()
        token_delete_entry = {
            "content": {
                "event": {
                    "@type": "http://example.com/core/event",
                    "dataCenter": "ORD1",
                    "environment": "TEST",
                    "eventTime": "2016-06-06T20:48:43.237Z",
                    "id": "1",
                    "product": {
                        "@type": "http://example.com/event/identity/token",
                        "resourceType": "TOKEN",
                        "serviceCode": "CloudIdentity",
                        "tenants": "test",
                        "version": "1"
                    },
                    "region": "ORD",
                    "resourceId": token_id,
                    "type": "DELETE",
                    "version": "1"
                }
            },
            "id": "urn:uuid:1",
        }
        feed['feed']['entry'].append(token_delete_entry)
        return json.dumps(feed)

    def _get_user_event(self, user_id, event_type, resource_type):
        feed = self._build_feed()
        suspended_user_entry = {
            "content": {
                "event": {
                    "@type": "http://example.com/core/event",
                    "dataCenter": "ORD1",
                    "environment": "TEST",
                    "eventTime": "2016-06-06T20:48:43.237Z",
                    "id": "1",
                    "product": {
                        "@type": "http://example.com/event/identity/user",
                        "resourceType": resource_type,
                        "serviceCode": "CloudIdentity",
                        "version": "1"
                    },
                    "region": "ORD",
                    "resourceId": user_id,
                    "type": event_type,
                    "version": "1"
                }
            },
            "id": "urn:uuid:1",
        }
        feed['feed']['entry'].append(suspended_user_entry)
        return json.dumps(feed)

    def _valid_get_response(self, content):
        """Valid get user response."""
        get_resp = requests.models.Response()
        get_resp.status_code = 200
        get_resp._content = content
        return get_resp

    @mock.patch('capstone.cache_invalidator.requests.Session.get')
    def test_revoke_token_event_invalidation(self, m):
        data = test_integration.generate_password_auth_data({
            "name": self.username,
            "password": self.password,
            "domain": {"id": self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        resp = self.authenticate(data)
        token2 = resp.headers['X-Subject-Token']
        # Assert tokens are equal for valid token
        self.assertEqual(token, token2)

        # Mock CloudFeeds response
        event = self._get_delete_token_event(token)
        m.return_value = self._valid_get_response(event)
        entry = cache_invalidator.Entry(self.client.entries[0])
        entry.invalidate()

        resp = self.authenticate(data)
        token2 = resp.headers['X-Subject-Token']
        # Assert tokens are different after invalidation
        self.assertNotEqual(token, token2)

    @mock.patch('capstone.cache_invalidator.requests.Session.get')
    def test_user_disabled_invalidation(self, m):
        data = test_integration.generate_password_auth_data({
            "name": self.username,
            "password": self.password,
            "domain": {"id": self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        resp = self.authenticate(data)
        token2 = resp.headers['X-Subject-Token']
        # Assert tokens are equal for valid token
        self.assertEqual(token, token2)

        # Mock CloudFeeds response
        user_id = resp.json()['token']['user']['id']
        event = self._get_user_event(user_id, "SUSPEND", "USER")
        m.return_value = self._valid_get_response(event)
        entry = cache_invalidator.Entry(self.client.entries[0])
        entry.invalidate()

        # Since the user did not actually get suspended, we can authenticate
        # and verify that a new token was issued.
        resp = self.authenticate(data)
        token2 = resp.headers['X-Subject-Token']
        # Assert tokens are different after invalidation
        self.assertNotEqual(token, token2)

    @mock.patch('capstone.cache_invalidator.requests.Session.get')
    def test_user_trr_invalidation(self, m):
        data = test_integration.generate_password_auth_data({
            "name": self.username,
            "password": self.password,
            "domain": {"id": self.domain_id},
        })
        resp = self.authenticate(data)
        token = resp.headers['X-Subject-Token']
        resp = self.authenticate(data)
        token2 = resp.headers['X-Subject-Token']
        # Assert tokens are equal for valid token
        self.assertEqual(token, token2)

        # Mock CloudFeeds response
        user_id = resp.json()['token']['user']['id']
        event = self._get_user_event(user_id, "DELETE", "TRR_USER")
        m.return_value = self._valid_get_response(event)
        entry = cache_invalidator.Entry(self.client.entries[0])
        entry.invalidate()

        # Since the user did not actually get suspended, we can authenticate
        # and verify that a new token was issued.
        resp = self.authenticate(data)
        token2 = resp.headers['X-Subject-Token']
        # Assert tokens are different after invalidation
        self.assertNotEqual(token, token2)
