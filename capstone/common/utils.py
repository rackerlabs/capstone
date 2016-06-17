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


def determine_x_forwarded_for_header(context):
    if not context:
        return

    if 'x-forwarded-for' not in context.get('header', []):
        return context['environment']['REMOTE_ADDR']
    else:
        return '{0}, {1}'.format(
            context['header']['x-forwarded-for'],
            context['environment']['REMOTE_ADDR'])


def get_scope(context):
    auth_params = context['environment']['openstack.params']['auth']
    scope = auth_params.get('scope', {})

    # NOTE(dstanek): support requests that are specifically unscoped
    if scope == 'unscoped':
        return {}

    return scope
