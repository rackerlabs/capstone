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

from keystone.common import config
from oslo_config import cfg


CONF = cfg.CONF

# Initialize configuration if 'default_config_files' is not an element of CONF.
if 'default_config_files' not in dir(CONF):
    config.configure()
    # Set default config values and load keystone.conf to setup caching
    # configurations.
    config.set_config_defaults()
    keystone_conf = os.environ.get('KEYSTONE_CONFIG',
                                   '/etc/keystone/keystone.conf')
    CONF(args=[], default_config_files=[keystone_conf])
