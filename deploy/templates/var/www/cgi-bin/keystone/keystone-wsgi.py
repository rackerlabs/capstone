# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os

import newrelic.agent
import pbr.version

from keystone.i18n import _LW
from keystone.server import wsgi as wsgi_server
from oslo_log import log
from oslo_log import versionutils

_version_ = pbr.version.VersionInfo('keystone').version_string()
newrelic.agent.initialize('/etc/keystone/newrelic.ini')

name = os.path.basename(__file__)
LOG = log.getLogger(__name__)


def deprecation_warning():
    versionutils.report_deprecated_feature(
        LOG,
        _LW('httpd/keystone.py is deprecated as of Mitaka'
            ' in favor of keystone-wsgi-admin and keystone-wsgi-public'
            ' and may be removed in O.')
    )
application = wsgi_server.initialize_application(
    name,
    post_log_configured_function=deprecation_warning
)
application = newrelic.agent.WSGIApplicationWrapper(application)
