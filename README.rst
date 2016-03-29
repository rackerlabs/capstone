Capstone
========

Entry points for `OpenStack Keystone <https://github.com/openstack/keystone>`_
in the Rackspace Public Cloud.

Design
------

Architecture
~~~~~~~~~~~~

The existing v2 identity system basically works like this:

.. image:: https://www.websequencediagrams.com/cgi-bin/cdraw?lz=dGl0bGUgdjIgQXV0aGVudGljYXRpb24gICAgICAAAQUAAQoAARQAHQwKVXNlci0-SmF2YSB2MjogdjIgYXV0aCByZXF1ZXN0AB4vAEAHLT5Vc2VyAEEMc3BvbnNl&s=napkin

.. https://www.websequencediagrams.com/ source:
   title v2 Authentication
   User->Java v2: v2 auth request
   Java v2->User: v2 auth response

Instead of impacting that system, we can build on top of it by deploying
keystone as a `reverse proxy <https://en.wikipedia.org/wiki/Reverse_proxy>`_ to
the existing v2 identity system:

.. image:: https://www.websequencediagrams.com/cgi-bin/cdraw?lz=IHRpdGxlIHYzIEF1dGhlbnRpY2F0aW9uICAgICAgAAEFAAEKAAEUAB0MCiBVc2VyLT5LZXlzdG9uZSB2MzogdjMgYXV0aCByZXF1ZXN0ACIsAD0LLT5KYXZhIHYyOiB2MgAdNAogADoHAIEPEABFCXNwb25zZQBnNVVzZXIAgV4MAEUG&s=napkin

.. https://www.websequencediagrams.com/ source:
   title v3 Authentication
   User->Keystone v3: v3 auth request
   Keystone v3->Java v2: v2 auth request
   Java v2->Keystone v3: v2 auth response
   Keystone v3->User: v3 auth response

Constraints
~~~~~~~~~~~

1. **Reliability.**

   - Keystone v3 should *never* impact the reliability of Rackspace v2 in any
     way.

   - Keystone v3 should regress gracefully when Rackspace v2 has outages,
     downtime, or inconsistent responses.

2. **Defcore-compliance.**

   - Keystone v3 must maintain complete Defcore compliance.

3. **Operational independence.**

   - Deploying Keystone v3 should not impact Rackspace v2 at all, or vice
     versa. You should be able to deploy new versions of either service
     independently of the other.

   - It should be trivial to vertically & horizontally scale as necessary.

4. **Seamless experience.**

   - Rackspace v2 is the single source of truth for authentication. Only
     Keystone v3-specific authorization data may live in Keystone.

5. **Performance.**

   - Keystone v3 should add minimal response time overhead to Rackspace v2.

Use cases
~~~~~~~~~

1. **Create a token.** This is required for defcore compliance. The returned
   token must work with existing OpenStack services, which currently use v2 for
   token validation.

   The following authentication claims are expected to be supported by the v3
   API:

   - ``token``

   - ``password`` + ``user_id``

   - ``password`` + ``user_name`` + ``user_domain_id``

   - ``password`` + ``user_name`` + ``user_domain_name``

   The following authorization scopes are supported by the v3 API:

   - Unscoped, or automatically scoped to a preferred project

   - Project-scoped: ``project_id``

   - Project-scoped: ``project_name`` + ``project_domain_id``

   - Project-scoped: ``project_name`` + ``project_domain_name``

   - Domain-scoped: ``domain_id``

   - Domain-scoped: ``domain_name``

2. **Validate a token.** Rackspace public cloud should use v3 internally, and
   the first step is to allow them to validate user tokens against Keystone.

3. **User account management.** Users should be able to update their own
   password and change their username with the same user experience as the v2
   API.

4. **Delegation.** Users should be able to use v3 to delegate authorization to
   each other (trusts or otherwise).

v3 ⟷ v2 attribute mapping
~~~~~~~~~~~~~~~~~~~~~~~~~

+-----------------------+--------------------+
| v3                    | v2                 |
+=======================+====================+
| user ID               | user ID            |
+-----------------------+--------------------+
| user name             | user name          |
+-----------------------+--------------------+
| user's domain ID      | user's tenant ID   |
+-----------------------+--------------------+
| user's domain name    | user's tenant name |
+-----------------------+--------------------+
| project ID            | sub-tenant ID      |
+-----------------------+--------------------+
| project name          | sub-tenant name    |
+-----------------------+--------------------+
| project's domain ID   | super-tenant ID    |
+-----------------------+--------------------+
| project's domain name | super-tenant name  |
+-----------------------+--------------------+
| domain ID             | tenant ID          |
+-----------------------+--------------------+
| domain name           | tenant name        |
+-----------------------+--------------------+

Testing
-------

Latest Build Results
~~~~~~~~~~~~~~~~~~~~

.. image:: https://app.wercker.com/status/409d943a74ce1d67a566d80ecbacd5fd/s/master
   :target: https://app.wercker.com/#applications/56bd3ba8239090c836084417

Definitions
~~~~~~~~~~~

API
  Tests that focus on a single API (as much as possible).
  An example would be verifying that you get a valid token back from user +
  password authentication. You may call validate on that token, but the intent
  is not to test validate, instead the intent is to test the auth API.

Functional
  Tests that cover user (including super type users) accessible
  APIs in business level scenarios.

Integration
  Developer tests that emphasize testing multiple systems.

Model based
  Tests that emphasizes an ASM or FSM approach to modeling the
  SUT(s).

Performance
  Tests that measure throughput and response time for a mixture
  of calls that approximates production usage, adjusted for the environment
  under test.

Reliability
  Testing to determine MTBF.

RPS
  Requests Per Second. Often a measurement of the amount of traffic a web
  server can handle.

Stress
  Testing at (progessively) higher levels of load inorder to
  determine breaking points.

SUT
  Abbreviation that stands for System Under Test.

System tests
  Similar to Dev Integration tests, but tend to be more from a black box
  perspective. 

Unit
  Tests which are focused on internal methods, functions or classes.

Unit tests
~~~~~~~~~~

Unit tests can be run in a local development environment using `tox
<https://testrun.org/tox/latest/>`_, simply by running tox::

    tox

Integration tests
~~~~~~~~~~~~~~~~~

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

First, you must run Capstone somewhere (see the *Deployment* section below).

Second, two files containing credentials for a Rackspace account must be on the
system . The first is ``~/.config/openstack/clouds.yaml``::

    ---
    clouds:
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

API
~~~

These will be mostly the DefCore tempest tests and Capstone API tests.

Performance
~~~~~~~~~~~

We will run the standard Rackspace Identity V2 mix with an additional 10 to 100
RPS made through Capstone Authenticate. Rackspace Identity has a large amount
of repeat calls, which is important since Capstone will cache authentication
calls to v2. It is important to reflect that in the mix of users to Capstone
authentication.

Model Based
~~~~~~~~~~~

We will be using model based tests to supplement, where time permits, the
integration tests. These tests will focus on switching between authentication
tokens issued through Capstone and directly through v2 with other v2 methods.
These will have lower priority than other testing.

Stress and Reliability
~~~~~~~~~~~~~~~~~~~~~~

We do not have a dedicated performance testing environment, so we will not be
able to perform stress or reliability testing.

System Testing
~~~~~~~~~~~~~~

System testing will focus on the following identified risk areas. Likely it
will be a combination of Model Based Tests and tests using the system test
framework for v2.

Risk Areas
..........

- Token compatibility

- Service catalog

- Caching mechanism

- RBAC

- Keystone specific authentication mechanisms

- Identity specific authentication mechanisms (MFA, Fed.)

- Repose V3 compatibility

Token Compatibility
###################

For the initial release, we only need to be concerned with v3 tokens used in
v2, since v3 will only support non-token related authentication. This area is
already covered by partially by the developer integration tests. Some
additional coverage is needed to do basic checks against a few other v2 APIs.
Those can be done as part of RBAC testing.

Service Catalog
###############

A user should be created through vanilla create user (i.e. without a numeric
domain.) and one with the one create user call.

Caching Mechanism
#################

It's likely Capstone will use a caching mechanism. Some testing will need to
be done to verify correct behavior for dirty caches. Special attention should
be made to token revocations, user updates, implicit token revocations (
changing a password, enabling mfa.)

RBAC
####

This testing should be around API's with different Identity RBAC rules: [
Identity Role Matrix] (https://one.rackspace.com/pages/viewpage.action?titl
e=Identity+Role+Matrix&spaceKey=auth). Testing doesn't need to be
exhaustive, but a couple of different test cases around each type of rule
should be sufficient.

- user admin in same domain

- user admin in different domain

- non user admin in same domain

- non user admin in different domain

- identity admin

- identity service admin

Keystone specific authentication mechanisms
###########################################

These are covered under API and integration testing. Some additional basic
ad hoc testing should be performed.

Identity specific authantication mechanisms
###########################################

MFA authentication should yield a reasonable error message in keystone.
Similar to attempting to use v3 federated authentication.

Repose V3 compatibility
#######################

It's not clear yet if this will be in scope for testing.


System Test Case List
.....................

Token Compatibility
###################

Currently Covered
+++++++++++++++++

- V3 token, V2 validate
- V2 token, V3 validate

To be added
+++++++++++

- V2 token, rescoping that token with V3 token authentication, with variations
  for scoping to project and domain

- V2 mfa token, V3 token auth

- V2 fed token, V3 token auth

- verify auth by is returned correctly

- expired tokens

- V2 mfa scoped token in V3 auth

- V2 password reset token in V3 auth

- V3 token used for impersonation in V2

- V2 impersonation token should be either be rejected in V3 or the
  impersonation bits should be ignored (security risk we should test for:
  you should not be able to get a real V3 token given a V2 impersonation token)

- V3 authenticate for user with mfa enabled

- V3 auth, V2 revoke

- V2 auth, V3 revoke ( 'revoke' not supported yet)

- V3 auth, then v2 get role, get tenant should return same results as
V2 auth then get *

Policy
######

Verify V3 methods are included/excluded according to the policy

Service Catalog
###############

- item by item comparison for

  - nast and mosso

  - default region


Caching
#######

- V3 authenticate, V2 remove mosso tenant, V3 should show updated service
catalog

- V3 authenticate, V2 revoke, V3 token auth should fail

- V3 authenticate, V2 password update, V3 token should be revoked

- V3 authenticate, V2 enable mfa, V3 token should be revoked

- others indirect revokes: disable user, disable domain, maybe pick a couple.

- V3 authenticate, V2 remove tenant, V3 tenant scoped authentication should
fail

- V3 authentication, V2 user disable (token should be revoked)

RBAC
####

V3 token scoped to a domain A, can't call add role to user (example) for
user in domain B

Continuous integration
~~~~~~~~~~~~~~~~~~~~~~

Our continuous integration process leverages `wercker <http://wercker.com/>`_.
With a local `docker server <https://www.docker.com/>`_ and the `wercker CLI
<http://wercker.com/cli/>`_ installed, you can replicate the CI process with::

    wercker build

Deployment
----------

Deployment tooling lives in the ``deploy/`` directory and uses `ansible
<https://www.ansible.com/>`_.

Prior to deploying capstone, specific upstream dependencies need to be
resolved. To resolve these using ``ansible-galaxy`` run the following::

    ansible-galaxy install --role-file=ansible-role-requirements.yml \
                           --ignore-errors --force

The ``deploy.yml`` playbook will expect an inventory file which will look
like::

    [keystone_all]
    <keystone_endpoint_ip_address>

The playbook will also expect us to provide a ``capstone.conf``::

    [service_admin]
    username = <username>
    password = <password>
    project_id = <project_id>
    rackspace_base_url = <rackspace_api_endpoint>

This account is provided by Rackspace. Once the ``capstone.conf`` and
``inventory`` files are in place we're ready to deploy::

    ansible-playbook -i inventory deploy.yml

Building
~~~~~~~~

Capstone uses very basic versioning. The following is an example of a capstone
build::

    capstone-0.1+be7bcf8.tar.gz

The SHA of the build ``be7bcf8`` is appended to be end of the version. A
specific version of capstone can be built by using the ``setup.py`` script.
Note that is it required to manually create a lightweight 0.1 tag. The tag will
only need to be created once, before you build capstone. This will be a manual
process until capstone is tagged properly upstream. The ``git tag`` command
will tag capstone at it's first commit::

    git tag 0.1 7fa2726
    git checkout be7bcf8
    python setup.py sdist

The resulting build will live under the ``capstone/dist/``. Note that ``pip``
will only recognize capstone as being version ``0.1``, regardless of the commit
that was used in the build.

Contributing
------------

Useful links:

- `Code reviews
  <https://review.gerrithub.io/#/dashboard/?title=Capstone&Capstone=is:open+project:rackerlabs/capstone&Deployment=is:open+project:rackerlabs/capstone-deploy>`_

- `Issue tracking
  <https://github.com/rackerlabs/capstone/issues>`_

Workflow
~~~~~~~~

The developer workflow `mirrors that of OpenStack
<http://docs.openstack.org/infra/manual/developers.html>`_ (refer here if
you're looking for additional detail), except that we host our code on
`github.com/rackerlabs <https://github.com/rackerlabs>`_ instead of
`github.com/openstack <https://github.com/openstack>`_, and therefore must also
use `GerritHub <https://gerrithub.io/>`_ instead of `review.openstack.org
<https://review.openstack.org/>`_ for code reviews. These differences result in
the following process:

- You'll first need a `GitHub <https://github.com/>`_ account, and then use
  that to authenticate with `GerritHub <https://gerrithub.io/>`_ (signing in
  with "DEFAULT" access is sufficient).

- Add your public SSH keys to both your `Github settings
  <https://github.com/settings/ssh>`_ and `GerritHub settings
  <https://review.gerrithub.io/#/settings/ssh-keys>`_ pages.

- Clone the repository: ``git clone git@github.com:rackerlabs/capstone.git &&
  cd capstone/``

- Setup ``git-review``: ``pip install --upgrade git-review && git review -s``

- Create a branch to work from, or go untracked: ``git checkout HEAD~0``

- Create a commit: ``git commit``.

  A ``Change-Id`` will be appended to your commit message to uniquely identify
  your code review.

- Upload it for review: ``git review``.

  You'll get a link to your code review on ``gerrithub.io``. A bot will then
  pull your change, run ``wercker build`` on it to test it, and upload the
  results back to gerrit, setting the ``Verified`` field to indicate build
  success or failure. If you have a Docker server available, you can run
  ``wercker build`` yourself using the `wercker CLI
  <https://github.com/wercker/wercker>`_.

- Your patch will be peer reviewed.

  If you need to upload a revision of your patch, fetch the latest patchset
  from gerrit using: ``git review -d <change-number>``, where your change
  number is NOT your ``Change-Id``, but instead is a unique number found in the
  URL of your code review.

- When your patch receives a +2 and is passing tests, it will be automatically
  merged.

