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
import logging
import requests
import sched
import time

from capstone.auth_plugin import RackspaceIdentity
from capstone import conf


logging.basicConfig(filename='/var/log/keystone/cache_invalidator.log',
                    level=logging.INFO)


class Entry(object):

    def __init__(self, entry):
        self._entry = entry

    def _get_type(self):
        return self._entry['content']['event']['type']

    def _get_resource_type(self):
        return self._entry['content']['event']['product']['resourceType']

    def invalidate(self):
        entry_type = self._get_type()
        resource_type = self._get_resource_type()
        if resource_type in ['USER', 'TRR_USER']:
            # Invalidate all tokens for updated/deleted user
            if entry_type in ['UPDATE', 'SUSPEND', 'DELETE']:
                user_id = self._entry['content']['event']['resourceId']
                logging.info('Invalidate tokens for updated/deleted user %s',
                             user_id)
        if resource_type == 'TOKEN':
            # Invalidate token by id
            if entry_type == 'DELETE':
                token_id = self._entry['content']['event']['resourceId']
                logging.info('Invalidate token %s', token_id)


class CloudFeedClient(object):

    def __init__(self, feed_url):
        self._feed_url = feed_url
        self._marker = None
        self._headers = {'Accept': 'application/vnd.rackspace.atom+json'}
        self._admin_client = RackspaceIdentity.from_admin_config()
        token_data = self._admin_client.authenticate()
        self._admin_token = token_data['access']['token']['id']
        self.entries = []

    def _page_feed(self, session, url):
        self._headers['X-Auth-Token'] = self._admin_token
        resp = session.get(url, headers=self._headers)
        if resp.status_code == requests.codes.ok:
            feed = json.loads(resp.content)['feed']
            if 'entry' in feed:
                self.entries = list(feed['entry']) + self.entries
            if 'previous' in resp.links:
                self._page_feed(session, resp.links['previous']['url'])
        elif resp.status_code == requests.codes.unauthorized:
            token_data = self._admin_client.authenticate()
            self._admin_token = token_data['access']['token']['id']
            logging.info('Authorization failed: Reauthenticating')
            self._page_feed(session, url)
        else:
            msg = 'Failed to parse feed: response code %s' % resp.status_code
            logging.info(msg)

    def parse(self):
        endpoint = (self._feed_url +
                    ("?marker=" + self._marker if self._marker else ""))
        self.entries = []
        s = requests.Session()
        self._page_feed(s, endpoint)
        if self.entries:
            self._marker = self.entries[0]['id']


def start(sc, client):
    client.parse()
    logging.info("Parsing %s events feed" % str(len(client.entries)))
    for entry in client.entries:
        event = Entry(entry)
        event.invalidate()
    sc.enter(int(conf.feed_delay), 1, start, (sc, client))


def main():
    feed_client = CloudFeedClient(conf.feed_url)
    s = sched.scheduler(time.time, time.sleep)
    s.enter(0, 1, start, (s, feed_client))
    s.run()
