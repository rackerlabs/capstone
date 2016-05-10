"""Mock implementation of v2.

This module provides a real web service that you can use perform real
integration testing against a mock of the v2 API.

Only the calls that Capstone needs to make are implemented.

For simplicity, user and tenant IDs are equivalent to the corresponding user
and tenant names, and a user's tenancy will match their domain ID.

"""

import datetime
import hashlib

import flask
from flask import request


app = flask.Flask('v2')

# Because this is only for testing, we can always run the app in debug mode.
app.debug = True


def hash_str(*args):
    """Hash the specified values together to provide predictable responses."""
    return hashlib.sha1(''.join(args)).hexdigest()


@app.route('/v2.0/users', methods=['GET'])
def get_user(user_id):
    user_id = request.args.get('user_id')

    # We only have a reason to support retrieving users by ID.
    if not user_id:
        raise NotImplementedError('List users not supported.')

    return flask.json.jsonify(**{
        "users": [
            {
                "RAX-AUTH:domainId": hash_str('account_id', user_id),
                "username": user_id,
                "enabled": True,
                "email": "%s@example.com" % user_id,
                "RAX-AUTH:defaultRegion": "IAD",
                "RAX-AUTH:multiFactorEnabled": False,
                "id": user_id,
            }
        ]
    })


@app.route('/v2.0/tokens', methods=['POST'])
def authenticate():
    username = request.json['auth']['passwordCredentials']['username']
    password = request.json['auth']['passwordCredentials']['password']

    # Authentication is valid if the password is the SHA1 hexdigest of the
    # username.
    if hash_str(username) != password:
        response = flask.json.jsonify(**{
            "unauthorized": {
                "message": "Unable to authenticate user with credentials"
                           " provided.",
                "code": 401
            }
        })
        response.status_code = 401
        return response

    tenant_id = hash_str('account_id', username)

    return flask.json.jsonify(**{
        "access": {
            "serviceCatalog": [
                {
                    "endpoints": [
                        {
                            "publicURL":
                                "https://iad.images.api.rackspacecloud.com/v2",
                            "region": "IAD",
                            "tenantId": tenant_id
                        },
                        {
                            "publicURL":
                                "https://dfw.images.api.rackspacecloud.com/v2",
                            "region": "DFW",
                            "tenantId": tenant_id
                        },
                    ],
                    "name": "cloudImages",
                    "type": "image"
                },
                {
                    "endpoints": [
                        {
                            "internalURL":
                                "https://snet-dfw.queues.api.rackspacecloud.co"
                                "m/v1/%s" % tenant_id,
                            "publicURL":
                                "https://dfw.queues.api.rackspacecloud.com/v1/"
                                "%s" % tenant_id,
                            "region": "DFW",
                            "tenantId": tenant_id
                        },
                        {
                            "internalURL":
                                "https://snet-iad.queues.api.rackspacecloud.co"
                                "m/v1/%s" % tenant_id,
                            "publicURL":
                                "https://iad.queues.api.rackspacecloud.com/v1/"
                                "%s" % tenant_id,
                            "region": "IAD",
                            "tenantId": tenant_id
                        }
                    ],
                    "name": "cloudQueues",
                    "type": "rax:queues"
                },
                {
                    "endpoints": [
                        {
                            "publicURL":
                                "https://iad.servers.api.rackspacecloud.com/v2"
                                "/%s" % tenant_id,
                            "region": "IAD",
                            "tenantId": tenant_id,
                            "versionId": "2",
                            "versionInfo":
                                "https://iad.servers.api.rackspacecloud.com/v"
                                "2",
                            "versionList":
                                "https://iad.servers.api.rackspacecloud.com/"
                        },
                        {
                            "publicURL":
                                "https://dfw.servers.api.rackspacecloud.com/v2"
                                "/%s" % tenant_id,
                            "region": "DFW",
                            "tenantId": tenant_id,
                            "versionId": "2",
                            "versionInfo":
                                "https://dfw.servers.api.rackspacecloud.com/v"
                                "2",
                            "versionList":
                                "https://dfw.servers.api.rackspacecloud.com/"
                        }
                    ],
                    "name": "cloudServersOpenStack",
                    "type": "compute"
                }
            ],
            "token": {
                "RAX-AUTH:authenticatedBy": [
                    "PASSWORD"
                ],
                "expires": '%sZ' % datetime.datetime.utcnow().isoformat()[:-3],
                "id": hash_str('token', username),
                "tenant": {
                    "id": tenant_id,
                    "name": tenant_id
                }
            },
            "user": {
                "RAX-AUTH:defaultRegion": "IAD",
                "id": username,
                "name": username,
                "roles": [
                    {
                        "description": "A Role that allows a user access to"
                                       " keystone Service methods",
                        "id": "6",
                        "name": ":default",
                        "tenantId": tenant_id
                    },
                    {
                        "description": "User Admin Role.",
                        "id": "3",
                        "name": "identity:user-admin"
                    }
                ]
            }
        }
    })
