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
import requests
import sched
import time

from keystone import exception
from keystone.i18n import _LI
from oslo_log import log

from capstone import auth_plugin
from capstone import conf


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

    def invalidate(self):
        """Invalidate entry.

        Invalidate capstone's cache by event type.
        """
        if self.resource_type in ['USER', 'TRR_USER']:
            # Invalidate all tokens for updated/deleted user
            if self.type in ['UPDATE', 'SUSPEND', 'DELETE']:
                user_id = self.resource_id
                LOG.info(_LI('Invalidate tokens for updated/deleted user %s'),
                         user_id)
        elif self.resource_type == 'TOKEN':
            # Invalidate token by id
            if entry_type == 'DELETE':
                token_id = self.resource_id
                LOG.info(_LI('Invalidate token %s'), token_id)


class CloudFeedClient(object):
    """Client to parse identity event feeds."""

    def __init__(self, feed_url):
        self._feed_url = feed_url
        self._marker = None
        self._headers = {'Accept': 'application/vnd.rackspace.atom+json'}
        self._admin_client = auth_plugin.RackspaceIdentity.from_admin_config()
        token_data = self._admin_client.authenticate()
        self._admin_token = token_data['access']['token']['id']
        self._entries = []

    def _page_feed(self, session, url, retry=True):
        """Page event feed(s).

        This method will read all events and add them to a list. This process
        of paging will continue until no previous url is returned in the links
        header.

        :param session: request session
        :param url: feed endpoint
        :param retry: boolean used for single re-authentication

        :raise keystone.exception.UnexpectedError: If response from feed is not
        200 OK and re-authentication failed.
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
            token_data = self._admin_client.authenticate()
            self._admin_token = token_data['access']['token']['id']
            LOG.info(_LI('Authorization failed: Re-authenticating'))
            self._page_feed(session, url, False)
        else:
            msg = (_LI('Failed to parse feed: response code %s') %
                   resp.status_code)
            LOG.info(msg)
            raise exception.UnexpectedError(msg)

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
    sc.enter(int(conf.polling_period), 1, start, (sc, client))


def main():
    client = CloudFeedClient(conf.feed_url)
    sc = sched.scheduler(time.time, time.sleep)
    # Method enter(delay, priority, action, argument)
    sc.enter(0, 1, start, (sc, client))
    sc.run()
