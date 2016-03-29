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

from six.moves import configparser


_config = configparser.ConfigParser()
_config.read(['/etc/capstone/capstone.conf',
              os.environ.get('CAPSTONE_CONFIG', '')])

admin_username = _config.get('service_admin', 'username')
admin_password = _config.get('service_admin', 'password')
admin_project_id = _config.get('service_admin', 'project_id')
rackspace_base_url = _config.get('rackspace', 'base_url').rstrip('/')
feed_url = _config.get('rackspace', 'feed_url').rstrip('/')
feed_delay = _config.get('rackspace', 'feed_delay')
