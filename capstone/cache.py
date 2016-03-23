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

from capstone import conf

from keystone.common import cache as keyston_cache
from oslo_cache import core as oslo_cache
from oslo_config import cfg


CAPSTONE_REGION = oslo_cache.create_region()
oslo_cache.configure_cache_region(cfg.CONF, CAPSTONE_REGION)

config_group = 'cache'
memoize = oslo_cache.get_memoization_decorator(
    conf.CONF, CAPSTONE_REGION, config_group)
