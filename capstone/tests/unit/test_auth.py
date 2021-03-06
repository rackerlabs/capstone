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
import testtools

from capstone.client import v2
from capstone.common import utils


class TestRackspaceIdentity(testtools.TestCase):

    def setUp(self):
        super(TestRackspaceIdentity, self).setUp()
        self.username = uuid.uuid4().hex
        self.password = uuid.uuid4().hex
        self.domain = uuid.uuid4().hex

    def test_correct_user_domain_id_from_roles(self):
        """Check the user's domain using the project IDs from the roles."""
        token_data = {
            'access': {
                'user': {
                    'id': uuid.uuid4().hex,
                    'roles': [
                        {'tenantId': uuid.uuid4().hex},
                        {'tenantId': self.domain},
                    ]
                }
            }
        }
        user_ref = {}
        identity = v2.RackspaceIdentity(
            self.username, self.password, user_ref,
            user_domain_id=self.domain)
        identity._assert_user_domain(token_data)

    def test_correct_user_domain_name_from_roles(self):
        """Check the user's domain using the project IDs from the roles."""
        token_data = {
            'access': {
                'user': {
                    'id': uuid.uuid4().hex,
                    'roles': [
                        {'tenantId': uuid.uuid4().hex},
                        {'tenantId': self.domain},
                    ]
                }
            }
        }
        user_ref = {}
        identity = v2.RackspaceIdentity(
            self.username, self.password, user_ref,
            user_domain_name=self.domain)
        identity._assert_user_domain(token_data)

    def test_correct_user_domain_id_from_Rackspace(self):
        """Check the user's domain using the data provided by Rackspace."""
        token_data = {
            'access': {
                'user': {
                    'id': uuid.uuid4().hex,
                    'roles': [
                        {'tenantId': uuid.uuid4().hex},
                        {'tenantId': uuid.uuid4().hex},
                    ]
                }
            }
        }
        identity = v2.RackspaceIdentity(
            self.username, self.password,
            user_domain_id=self.domain,
            user_ref={'RAX-AUTH:domainId': self.domain})
        identity._assert_user_domain(token_data)

    def test_correct_user_domain_name_from_Rackspace(self):
        """Check the user's domain using the data provided by Rackspace."""
        token_data = {
            'access': {
                'user': {
                    'id': uuid.uuid4().hex,
                    'roles': [
                        {'tenantId': uuid.uuid4().hex},
                        {'tenantId': uuid.uuid4().hex},
                    ]
                }
            }
        }
        identity = v2.RackspaceIdentity(
            self.username, self.password, user_domain_name=self.domain,
            user_ref={'RAX-AUTH:domainId': self.domain})
        identity._assert_user_domain(token_data)

    def test_incorrect_user_domain(self):
        token_data = {
            'access': {
                'user': {
                    'id': uuid.uuid4().hex,
                    'roles': [
                        {'tenantId': uuid.uuid4().hex},
                        {'tenantId': uuid.uuid4().hex},
                    ]
                }
            }
        }
        identity = v2.RackspaceIdentity(
            self.username, self.password,
            scope_domain_id=self.domain,
            user_ref={'RAX-AUTH:domainId': uuid.uuid4().hex})
        self.assertRaises(exception.Unauthorized,
                          identity._assert_domain_scope, token_data)

    def test_correct_domain_scope_from_roles(self):
        """Check the domain scope using the project IDs from the roles."""
        token_data = {
            'access': {
                'user': {
                    'id': uuid.uuid4().hex,
                    'roles': [
                        {'tenantId': uuid.uuid4().hex},
                        {'tenantId': self.domain},
                    ]
                }
            }
        }
        identity = v2.RackspaceIdentity(
            self.username, self.password,
            scope_domain_id=self.domain,
            user_ref={'RAX-AUTH:domainId': self.domain})
        identity._assert_domain_scope(token_data)

    def test_correct_domain_scope_from_Rackspace(self):
        """Check the domain scope using the data provided by Rackspace."""
        token_data = {
            'access': {
                'user': {
                    'id': uuid.uuid4().hex,
                    'roles': [
                        {'tenantId': uuid.uuid4().hex},
                        {'tenantId': uuid.uuid4().hex},
                    ]
                }
            }
        }
        identity = v2.RackspaceIdentity(
            self.username, self.password,
            scope_domain_id=self.domain,
            user_ref={'RAX-AUTH:domainId': self.domain})
        identity._assert_domain_scope(token_data)

    def test_incorrect_domain_scope(self):
        token_data = {
            'access': {
                'user': {
                    'id': uuid.uuid4().hex,
                    'roles': [
                        {'tenantId': uuid.uuid4().hex},
                        {'tenantId': uuid.uuid4().hex},
                    ]
                }
            }
        }
        identity = v2.RackspaceIdentity(
            self.username, self.password,
            scope_domain_id=self.domain,
            user_ref={'RAX-AUTH:domainId': uuid.uuid4().hex})
        self.assertRaises(exception.Unauthorized,
                          identity._assert_domain_scope, token_data)

    def test_update_headers_with_x_forwarded_for_header(self):
        context = {
            'environment': {
                'REMOTE_ADDR': '127.0.0.1'
            }
        }

        header = utils.determine_x_forwarded_for_header(context)
        self.assertEqual(header, '127.0.0.1')

    def test_update_headers_with_existing_x_forwarded_for_header(self):
        context = {
            'environment': {
                'REMOTE_ADDR': '127.0.0.1'
            },
            'header': {
                'x-forwarded-for': '127.0.0.3'
            }
        }

        header = utils.determine_x_forwarded_for_header(context)
        self.assertEqual(header, '127.0.0.3, 127.0.0.1')

    def test_update_headers_with_x_forwarded_for_header_without_context(self):
        header = utils.determine_x_forwarded_for_header(context=None)
        self.assertIsNone(header)

        header = utils.determine_x_forwarded_for_header(context={})
        self.assertIsNone(header)
