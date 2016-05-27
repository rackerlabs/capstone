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
import sched
import time

from keystone.i18n import _LI
from oslo_log import log
import requests

from capstone import auth_plugin
from capstone import cache
from capstone import conf
from capstone import const


CONF = conf.CONF
LOG = log.getLogger(__name__)


class Entry(object):
    """Entry for invalidation."""

    def __init__(self, entry):
        self._entry = entry

    @property
    def type(self):
        return self._entry['content']['event']['type']

    @property
    def resource_id(self):
        return self._entry['content']['event']['resourceId']

    @property
    def resource_type(self):
        return self._entry['content']['event']['product']['resourceType']

    def _generate_key(self, arguments):
        """Generate key by given arguments."""
        kw_args = {}
        key_function = cache.user_region.function_key_generator(
            arguments,
            auth_plugin.RackspaceIdentity._get_user,
            **kw_args
        )
        # Return key and remove trailing pipe character
        return key_function()[:-1]

    def invalidate(self):
        """Invalidate entry.

        Invalidate capstone's cache by event type.
        """
        if (self.resource_type in ['USER', 'TRR_USER'] and
                self.type in ['UPDATE', 'SUSPEND', 'DELETE']):
            # Invalidate token for updated/suspended/deleted user
            if cache.token_region.get(self.resource_id):
                cache.token_region.delete(self.resource_id)
                LOG.info(_LI('Invalidate tokens for updated/suspended/deleted '
                             'user %s'), self.resource_id)

            user = get_user(self.resource_id)
            if self.type == 'UPDATE' and user:
                # Attempt to delete user's entry in cache if an identity update
                # event feed was issued.
                arguments_by_name = '%s %s' % (
                    '/users',
                    {'name': unicode(user['username'])}
                )
                arguments_by_id = '%s/%s' % ('/users', user['id'])
                cache.user_region.delete(self._generate_key(arguments_by_id))
                cache.user_region.delete(self._generate_key(arguments_by_name))
        elif self.resource_type == 'TOKEN' and self.type == 'DELETE':
            # Invalidate token by id
            user_id = cache.token_map_region.get(self.resource_id)
            if user_id:
                cache.token_map_region.delete(self.resource_id)
                cache.token_region.delete(user_id)
                LOG.info(_LI('Invalidate token SHA{%s}'),
                         hashlib.sha1(self.resource_id).hexdigest)


def get_user(user_id, retry=True):
    user_url = CONF.rackspace.base_url + '/users/' + user_id
    headers = const.HEADERS
    headers['X-Auth-Token'] = get_admin_token()
    resp = requests.get(user_url, headers=headers)
    if resp.status_code == requests.codes.ok:
        return resp.json()['user']
    elif retry:
        return get_user(user_id, retry=False)
    else:
        msg = (_LI('Failed to retrieve user from v2: response code %s') %
               resp.status_code)
        LOG.info(msg)


def get_admin_token(retry=True):
    """Authentication request to v2.

    Make a v2 authentication request to retrieve an admin token. Retry on
    first failure.
    """
    data = {
        "auth": {
            "passwordCredentials": {
                "username": CONF.service_admin.username,
                "password": CONF.service_admin.password,
            },
        },
    }
    token_url = CONF.rackspace.base_url + '/tokens'
    resp = requests.post(token_url, headers=const.HEADERS, json=data)
    if resp.status_code == requests.codes.ok:
        token_data = resp.json()
        return token_data['access']['token']['id']
    elif retry:
        return get_admin_token(retry=False)
    else:
        msg = (_LI('Authentication failed against v2: response code %s') %
               resp.status_code)
        LOG.info(msg)
        raise RuntimeError(msg)


class CloudFeedClient(object):
    """Client to parse identity event feeds."""

    def __init__(self, feed_url):
        self._feed_url = feed_url
        self._marker = None
        self._headers = {'Accept': 'application/vnd.rackspace.atom+json'}
        self._admin_token = get_admin_token()
        self._entries = []

    def _page_feed(self, session, url, retry=True):
        """Page event feed(s).

        This method will read all events and add them to a list. This process
        of paging will continue until no previous url is returned in the links
        header.

        :param session: request session
        :param url: feed endpoint
        :param retry: boolean used for single re-authentication

        :raise SystemExit: If response from feed is not 200 OK and
        re-authentication failed.
        """
        self._headers['X-Auth-Token'] = self._admin_token
        resp = session.get(url, headers=self._headers)
        if resp.status_code == requests.codes.ok:
            feed = json.loads(resp.content)['feed']
            if 'entry' in feed:
                self._entries = list(feed['entry']) + self._entries
            if 'previous' in resp.links:
                self._page_feed(session, resp.links['previous']['url'])
        elif resp.status_code == requests.codes.unauthorized and retry:
            self._admin_token = get_admin_token()
            LOG.info(_LI('Authorization failed: Re-authenticating'))
            self._page_feed(session, url, False)
        else:
            msg = (_LI('Failed to parse feed: response code %s') %
                   resp.status_code)
            LOG.info(msg)
            raise RuntimeError(msg)

    def _parse(self):
        """Parse events.

        This method will set and use an event id marker to denote the last
        event parsed.
        """
        endpoint = (self._feed_url +
                    ("?marker=" + self._marker if self._marker else ""))
        self._entries = []
        s = requests.Session()
        self._page_feed(s, endpoint)
        if self._entries:
            self._marker = self._entries[0]['id']

    @property
    def entries(self):
        self._parse()
        LOG.info(_LI("Parsing %d event feed(s)"), len(self._entries))
        return self._entries


def start(sc, client):
    for entry in client.entries:
        event = Entry(entry)
        event.invalidate()
    sc.enter(CONF.rackspace.polling_period, 1, start, (sc, client))


def main():
    try:
        client = CloudFeedClient(CONF.rackspace.feed_url)
        sc = sched.scheduler(time.time, time.sleep)
        # Method enter(delay, priority, action, argument)
        sc.enter(0, 1, start, (sc, client))
        sc.run()
    except RuntimeError as e:
        raise SystemExit(e.message)
