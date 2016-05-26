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

import logging
import os
import sys

from oslo_config import cfg


CONF = cfg.CONF
CONF.register_opt(
    cfg.StrOpt('base_url',
               help='Base URL to be used to build v2 Identity URLs.'),
    group='rackspace')
CONF.register_opt(
    cfg.StrOpt('feed_url',
               help='URL used for reading identity feed events.'),
    group='rackspace')
CONF.register_opt(
    cfg.IntOpt('polling_period',
               help='Polling period in seconds to read identity feed events.',
               default=60),
    group='rackspace')
CONF.register_opt(
    cfg.StrOpt('id',
               help='ID for the Identity service admin.'),
    group='service_admin')
CONF.register_opt(
    cfg.StrOpt('username',
               help='Username for the Identity service admin.'),
    group='service_admin')
CONF.register_opt(
    cfg.StrOpt('password', secret=True,
               help='Password for the Identity service admin.'),
    group='service_admin')
CONF.register_opt(
    cfg.StrOpt('project_id',
               help='Project ID for the Identity service admin.'),
    group='service_admin')
CONF.register_opt(
    cfg.BoolOpt('caching', default=True,
                help='Toggle for capstone caching. This has no '
                     'effect unless global caching is enabled.'),
    group='capstone')
CONF.register_opt(
    cfg.IntOpt('cache_time', default=60,
               help='Time to cache capstone data (in seconds). This has '
                    'no effect unless global and capstone caching are '
                    'enabled.'),
    group='capstone')

# Setup cache invalidator configuration
if os.path.basename(sys.argv[0]) == 'capstone-cache-invalidator':
    CONF(default_config_files=[])
    logging_config_file = os.environ.get('CACHE_INVALIDATOR_LOGGING_CONFIG',
                                         '/etc/keystone/logging.conf')
    logging.config.fileConfig(logging_config_file)
    CONF.log_opt_values(logging.getLogger(CONF.prog), logging.INFO)

# $CAPSTONE_CONFIG takes precedence over the default config file.
config_file = os.environ.get(
    'CAPSTONE_CONFIG', '/etc/capstone/capstone.conf')
if os.path.isfile(config_file):
    CONF.default_config_files.append(config_file)
    CONF.reload_config_files()

admin_id = CONF.service_admin.id
admin_username = CONF.service_admin.username
admin_password = CONF.service_admin.password
admin_project_id = CONF.service_admin.project_id
rackspace_base_url = CONF.rackspace.base_url.rstrip('/')
