#!/usr/bin/env python

"""Mock implementation of v2.

This module provides a real web service that you can use perform real
integration testing against a mock of the v2 API.

Only the calls that Capstone needs to make are implemented.

For simplicity, user and tenant IDs are equivalent to the corresponding user
and tenant names, and a user's tenancy will match their domain ID.

"""

import datetime
import hashlib
import json
import re
import sys
import wsgiref.simple_server


# content type headers
PLAIN_TEXT = ('Content-type', 'plain/text')
APP_JSON = ('Content-type', 'application/json')

# Because this is only for testing, we can always run the app in debug mode.
app.debug = True


def hash_str(*args):
    """Hash the specified values together to provide predictable responses."""
    return hashlib.sha1(''.join(args)).hexdigest()


def get_user(environ, start_response):
    user_id = environ['wsgi.match'].group()

    data = json.dumps({
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
    start_response('200 OK', [APP_JSON])
    return [data]


def authenticate(environ, start_response):
    content_len = int(environ['CONTENT_LENGTH'])
    request_body = json.loads(environ['wsgi.input'].read(content_len))
    username = request_body['auth']['passwordCredentials']['username']
    password = request_body['auth']['passwordCredentials']['password']

    # Authentication is valid if the password is the SHA1 hexdigest of the
    # username.
    if hash_str(username) != password:
        data = json.dumps({
            "unauthorized": {
                "message": "Unable to authenticate user with credentials"
                           " provided.",
                "code": 401
            }
        })
        start_response('401 Unauthorized', [APP_JSON])
        return [data]

    tenant_id = hash_str('account_id', username)

    data = json.dumps({
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
    start_response('200 OK', [APP_JSON])
    return [data]


def _not_found(environ, start_response):
    """Micro application returning a 404 and all the environment vars.

    This is useful for debugging. Just hit a url that doesn't exist,
    like '/', and see what is getting setup.
    """
    start_response('404 Not Found', [PLAIN_TEXT])
    return ["%s: %s\n" % (key, value) for key, value in environ.iteritems()]


def application(environ, start_response):
    """Main application entrypoint."""
    for (method, pattern), micro_app in routes:
        match = matches(method, pattern, environ)
        if match:
            environ['wsgi.match'] = match
            return micro_app(environ, start_response)
    return _not_found(environ, start_response)


def matches(method, pattern, environ):
    if environ['REQUEST_METHOD'] != method:
        return None
    return re.match(pattern, environ['PATH_INFO'])


routes = (
    (('GET', r'^/v2.0/users/(\w+)$'), get_user),
    (('POST', r'^/v2.0/tokens/?$'), authenticate),
)

if __name__ == '__main__':
    try:
        port = int(sys.argv[1])
    except IndexError:
        port = 8000
    httpd = wsgiref.simple_server.make_server('', port, application)
    print("Serving on port %s..." % port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
