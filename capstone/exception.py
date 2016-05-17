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

from keystone import exception
from keystone.i18n import _


class BadGateway(exception.Error):
    message_format = _("The server, while acting as a gateway or proxy, "
                       "received an invalid response from the upstream server "
                       "it accessed in attempting to fulfill the request.")
    code = 502
    title = 'Bad Gateway'
