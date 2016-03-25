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

import os

from oslo_config import cfg


#CONF = cfg.ConfigOpts()
CONF = cfg.CONF
CONF.register_opt(
    cfg.StrOpt('base_url',
               help='Base URL to be used to build v2 Identity URLs.'),
    group='rackspace')
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

possible_config_files = [
    '/etc/capstone/capstone.conf',
    os.environ.get('CAPSTONE_CONFIG', ''),
]
possible_config_files = [c for c in possible_config_files
                         if os.path.isfile(c)]
CONF.default_config_files.extend(possible_config_files)
CONF._parse_config_files()

admin_username = CONF.service_admin.username
admin_password = CONF.service_admin.password
admin_project_id = CONF.service_admin.project_id
rackspace_base_url = CONF.rackspace.base_url.rstrip('/')
