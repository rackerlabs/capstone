#!/usr/bin/python

import sys

from os_client_config import config as cloud_config
import requests


class AuthArgs(object):

    def __init__(self, rax_cloud_name, keystone_cloud_name):
        cloud_cfg = cloud_config.OpenStackConfig()

        rax_cloud = cloud_cfg.get_one_cloud(rax_cloud_name)
        self.rax_args = rax_cloud.get_auth_args()

        keystone_cloud = cloud_cfg.get_one_cloud(keystone_cloud_name)
        keystone_args = keystone_cloud.get_auth_args()
        self.keystone_auth_url = keystone_args['auth_url']

    def v2_args(self):
        args = self.rax_args.copy()
        args['auth_url'] = '%s/tokens' % args['auth_url'].rstrip('/')
        return args

    def v3_args(self):
        args = self.rax_args.copy()  # ensure Rackspace credentials for V3
        args['auth_url'] = ('%s/auth/tokens'
                            % self.keystone_auth_url.rstrip('/'))
        return args


def run_keypair_list(token, project_id):
    url = ('https://iad.servers.api.rackspacecloud.com/v2/%s/os-keypairs'
            % project_id)
    headers = {
        'User-Agent': 'capstone/0.1',
        'Content-Type': 'application/json',
        'X-Auth-Token': token,
    }
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_v2_token_from_rackspace(username, password, project_id, auth_url):
    headers = {'Content-Type': 'application/json'}
    data = {
        "auth": {
            "passwordCredentials": {
                "username": username,
                "password": password,
            },
            "tenantId": project_id,
        },
    }
    resp = requests.post(auth_url, headers=headers, json=data)
    resp.raise_for_status()
    return resp.json()['access']['token']['id']


def get_v3_default_scoped_token_from_keystone(username, password, project_id,
                                              auth_url):
    headers = {'Content-Type': 'application/json'}
    data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "password": password,
                        "domain": {"id": project_id},
                    },
                },
            },
        },
    }
    resp = requests.post(auth_url, headers=headers, json=data)
    resp.raise_for_status()
    return resp.headers['X-Subject-Token']


def get_v3_project_scoped_token_from_keystone(username, password, project_id,
                                              auth_url):
    headers = {'Content-Type': 'application/json'}
    data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "password": password,
                        "domain": {"id": project_id},
                    },
                },
            },
            "scope": {
                "project": {
                    "name": project_id,
                    "domain": {"id": project_id},
                }
            },
        },
    }
    resp = requests.post(auth_url, headers=headers, json=data)
    resp.raise_for_status()
    return resp.headers['X-Subject-Token']


def get_v3_domain_scoped_token_from_keystone(username, password, project_id,
                                             auth_url):
    headers = {'Content-Type': 'application/json'}
    data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "password": password,
                        "domain": {"id": project_id},
                    },
                },
            },
            "scope": {
                "domain": {"id": project_id},
            },
        },
    }
    resp = requests.post(auth_url, headers=headers, json=data)
    resp.raise_for_status()
    return resp.headers['X-Subject-Token']


def test(token_type, **auth_args):
    print('Getting %s' % token_type)
    func = globals()['get_%s' % token_type.lower().replace(' ', '_')]
    token = func(**auth_args)
    print('  received: %s...' % token[:32])
    print('Using Keystone token to list keys')
    keypairs = run_keypair_list(token, auth_args['project_id'])
    print('  we found %d keypair(s)' % len(keypairs['keypairs']))
    print()


def main():
    if len(sys.argv) != 3:
        print('usage: ./test.py rax_cloud_name keystone_cloud_name')
        print('   rax_cloud_name is the name of the Rackspace cloud from '
              'your clouds.yml file')
        print('   keystone_cloud_name is the name of the Keystone cloud from '
              'your clouds.yml file')
        print('   e.g. ./test.py rax openstack')
        sys.exit(1)

    rax_cloud_name = sys.argv[1]
    keystone_cloud_name = sys.argv[2]

    auth_args = AuthArgs(rax_cloud_name, keystone_cloud_name)

    test('v2 token from Rackspace', **auth_args.v2_args())
    test('v3 default scoped token from Keystone', **auth_args.v3_args())
    test('v3 project scoped token from Keystone', **auth_args.v3_args())
    test('v3 domain scoped token from Keystone', **auth_args.v3_args())

    return 0


if __name__ == '__main__':
    sys.exit(main())
