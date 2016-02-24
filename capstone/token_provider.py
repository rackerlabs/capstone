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

"""Rax Compatibility Token Provider."""

import hashlib

from keystone.auth import controllers
from keystone.common import utils
from keystone import exception
from keystone.i18n import _
from keystone.token import provider
from keystone.token.providers import common
from oslo_log import log
import six


LOG = log.getLogger(__name__)

controllers.Auth._check_and_set_default_scoping = lambda *a, **k: None
controllers.AuthInfo._validate_and_normalize_scope_data = lambda *a, **k: None


class RaxTokenDataHelper(object):

    def __init__(self, rax_token_data):
        self.rax_token_data = rax_token_data

    def _populate_scope(self, token_data, domain_id, project_id):
        # TODO(dstanek): always a project scoped token?
        token_data['project'] = (
            self.rax_token_data['access']['token']['tenant'])
        project_id = token_data['project']['id']
        token_data['project']['domain'] = {
            'id': project_id,
            'name': project_id,
        }

    def _populate_user(self, token_data, user_id, trust):
        token_data['user'] = {
            'id': self.rax_token_data['access']['user']['id'],
            'name': self.rax_token_data['access']['user']['name'],
            # Is this correct?
            'domain': self.rax_token_data['access']['token']['tenant'],
        }

    def _populate_roles(self, token_data, user_id, domain_id, project_id,
                        trust, access_token):
        roles = []
        for role in self.rax_token_data['access']['user']['roles']:
            roles.append({'id': role['id'], 'name': role['name']})
        token_data['roles'] = roles

    def _populate_service_catalog(self, token_data, user_id,
                                  domain_id, project_id, trust):
        if 'catalog' in token_data:
            # no need to repopulate service catalog
            return

        # TODO(dstanek): probably reformat to look like a Keystone catalog
        catalog = self._reformat_catalog(
            self.rax_token_data['access']['serviceCatalog'])
        token_data['catalog'] = catalog

    def _populate_token_dates(self, token_data, expires=None, trust=None,
                              issued_at=None):
        if not expires:
            expires = provider.default_expire_time()
        if not isinstance(expires, six.string_types):
            expires = utils.isotime(expires, subsecond=True)
        token_data['expires_at'] = expires
        token_data['issued_at'] = (issued_at or utils.isotime(subsecond=True))

    def _populate_audit_info(self, token_data, audit_info=None):
        if audit_info is None or isinstance(audit_info, six.string_types):
            token_data['audit_ids'] = provider.audit_info(audit_info)
        elif isinstance(audit_info, list):
            token_data['audit_ids'] = audit_info
        else:
            msg = (_('Invalid audit info data type: %(data)s (%(type)s)') %
                   {'data': audit_info, 'type': type(audit_info)})
            LOG.error(msg)
            raise exception.UnexpectedError(msg)

    def _reformat_catalog(self, rax_catalog):
        def _expand_endpoints(rax_endpoint, rax_service):
            for interface in ('adminURL', 'internalURL', 'publicURL'):
                if interface in rax_endpoint:
                    url = rax_endpoint[interface]
                    interface = interface[:-3]

                    id_sha = hashlib.sha1(
                        rax_service['name'] + rax_service['type'] +
                        interface + rax_endpoint.get('region', '') + url)
                    endpoint = {
                        'id': id_sha.hexdigest(),
                        'region': rax_endpoint.get('region'),
                        'interface': interface,
                        'url': url,
                    }
                    yield endpoint

        catalog = []
        for rax_service in rax_catalog:
            id_sha = hashlib.sha1(rax_service['name'] + rax_service['type'])
            service = {
                'id': id_sha.hexdigest(),
                'name': rax_service['name'],
                'type': rax_service['type'],
                'endpoints': [],
            }
            for rax_endpoint in rax_service['endpoints']:
                service['endpoints'].extend(
                    _expand_endpoints(rax_endpoint, rax_service))

            catalog.append(service)

        return catalog

    def get_token_data(self, user_id, method_names, extras=None,
                       domain_id=None, project_id=None, expires=None,
                       trust=None, token=None, include_catalog=True,
                       bind=None, access_token=None, issued_at=None,
                       audit_info=None):
        token_data = {
            'methods': method_names,
            'rax:token_response': self.rax_token_data,
        }

        # Rax doesn't have projects that act as domains
        token_data['is_domain'] = False

        self._populate_scope(token_data, domain_id, project_id)
        self._populate_user(token_data, user_id, trust)
        self._populate_roles(token_data, user_id, domain_id, project_id, trust,
                             access_token)
        self._populate_audit_info(token_data, audit_info)

        if include_catalog:
            self._populate_service_catalog(token_data, user_id, domain_id,
                                           project_id, trust)
        self._populate_token_dates(token_data, expires=expires, trust=trust,
                                   issued_at=issued_at)
        return {'token': token_data}


class Provider(common.BaseProvider):
    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)
        self.v3_token_data_helper = None

    def _get_token_id(self, token_data):
        raw_token = self.v3_token_data_helper.rax_token_data
        return raw_token['access']['token']['id'].encode('utf-8')

    @property
    def _supports_bind_authentication(self):
        """Token bind is not supported by this token provider."""
        return False

    def needs_persistence(self):
        """Should the token be written to a backend."""
        return False

    def issue_v3_token(self, user_id, method_names, expires_at=None,
                       project_id=None, domain_id=None, auth_context=None,
                       trust=None, metadata_ref=None, include_catalog=True,
                       parent_audit_id=None):
        expires_at = (
            auth_context['rax:token_response']['access']['token']['expires'])
        self.v3_token_data_helper = RaxTokenDataHelper(
            auth_context['rax:token_response'])
        try:
            return super(Provider, self).issue_v3_token(
                user_id,
                method_names,
                expires_at=expires_at,
                project_id=project_id,
                domain_id=domain_id,
                auth_context=auth_context,
                trust=trust,
                metadata_ref=metadata_ref,
                include_catalog=include_catalog,
                parent_audit_id=parent_audit_id)
        finally:
            self.v3_token_data_helper = None

    def validate_v3_token(self, token_ref):
        raise NotImplemented
        self.v3_token_data_helper = RaxTokenDataHelper(None)
        try:
            return super(Provider, self).validate_v3_token(token_ref)
        finally:
            self.v3_token_data_helper = None
