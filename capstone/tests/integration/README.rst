Integration Tests
=================

Integration tests against Capstone and the Rackspace v2.0 Identity API. The
test executes the following flow:

.. image::
    https://www.websequencediagrams.com/cgi-bin/cdraw?lz=dGl0bGUgSW50ZWdyYXRpb24gdGVzdCBmbG93CgAKDFRlc3QgLT4gUmFja3NwYWNlIHYyLjAgRW5kcG9pbnQ6IHYyIGF1dGggcmVxdWVzdAoAEhcgLT4AYQ1UZXMAMA1zcG9uc2UATS5jYW4gSSBkbyBzb21ldGhpbmcgdXNlZnVsIHdpdGggdGhpcyB0b2tlbj8AaC5saXN0IG9mIGtleSBwYWlycwCBfRVLZXlzdG9uZSB2MwCCAwwzAIIBDgASFACBdRcAMQkAb4Ed&s=napkin

.. https://www.websequencediagrams.com/ source:
   title Integration test flow
   Integration Test -> Rackspace v2.0 Endpoint: v2 auth request
   Rackspace v2.0 Endpoint -> Integration Test: v2 auth response
   Integration Test -> Rackspace v2.0 Endpoint: can I do something useful with this token?
   Rackspace v2.0 Endpoint -> Integration Test: list of key pairs
   Integration Test -> Keystone v3 Endpoint: v3 auth request
   Keystone v3 Endpoint -> Integration Test: v3 auth response
   Integration Test -> Rackspace v2.0 Endpoint: can I do something useful with this token?
   Rackspace v2.0 Endpoint -> Integration Test: list of key pairs

These tests require additional information in order to be run successfully. In
order to run these tests, the following steps must be done.

First, you must run Capstone somewhere. Deployment tooling for the Capstone
project can be found in `capstone-deploy <https://github.com/rackerlabs/capstone-deploy>`_.

Second, two files containing credentials for a Rackspace account must be on the
system . The first file should contain a Rackspace service account used to make
admin request against Rackspace's v2.0 API and a test user account to run
integration test against.

``~/.config/openstack/clouds.yaml``::

    ---
    clouds:
      rackspace_admin:
        profile: rackspace
          auth:
            username: <admin_username>
            password: <admin_password>
      rackspace:
        profile: rackspace
          auth:
            domain_id: <domain_id>
              project_id: <account_id>
              user_id: <user_id>
              username: <username>
              password: <password>
          region_name: <region_id>
        keystone:
          profile: capstone

The second file is ``~/.config/openstack/clouds-public.yaml``::

    ---
    public-clouds:
      rackspace:
        auth:
          auth_url: https://identity.api.rackspacecloud.com/v2.0/
      capstone:
        auth:
          auth_url: http://localhost:5000/v3/

The integration test will use ``os-cloud-config`` to parse these files to build
requests to make against both the Rackspace endpoint and the Keystone endpoint.
The tests can be run through ``tox``::

    tox -e integration

Or any python test runner::

    python -m unittest \
    capstone.tests.integration.test_integration.IntegrationTests
