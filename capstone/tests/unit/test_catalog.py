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
import json
import os

import testtools

from capstone import token_provider


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestCatalogReformatting(testtools.TestCase):
    """Checks the V3 catalog format."""

    def setUp(self):
        super(TestCatalogReformatting, self).setUp()
        filename = os.path.join(FIXTURES_DIR, 'rackspace_auth_response.json')
        with open(filename) as f:
            self.auth_response_body = json.load(f)

    def _check_service_ids(self, catalog):
        for service in catalog:
            expected_id_sha = hashlib.sha1(service['name'] + service['type'])
            self.assertEqual(expected_id_sha.hexdigest(), service['id'])

    def _check_endpoint_ids(self, catalog):
        for service in catalog:
            for endpoint in service['endpoints']:
                region = endpoint['region'] or ''
                expected_id_sha = hashlib.sha1(
                    service['name'] + service['type'] +
                    endpoint['interface'] + region +
                    endpoint['url'])
                self.assertEqual(expected_id_sha.hexdigest(), endpoint['id'])

    def test(self):
        tdh = token_provider.RackspaceTokenDataHelper(self.auth_response_body)

        v3catalog = tdh._reformat_catalog(
            self.auth_response_body['access']['serviceCatalog'])
        self._check_service_ids(v3catalog)
        self._check_endpoint_ids(v3catalog)
        json.dump(v3catalog, open('/tmp/test.done.json', 'w'), indent=4)
