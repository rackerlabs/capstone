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

.. image:: https://app.wercker.com/status/409d943a74ce1d67a566d80ecbacd5fd/s/master
   :target: https://app.wercker.com/#applications/56bd3ba8239090c836084417

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

Continuous integration
~~~~~~~~~~~~~~~~~~~~~~

Our continuous integration process leverages `wercker <http://wercker.com/>`_.
With a local `docker server <https://www.docker.com/>`_ and the `wercker CLI
<http://wercker.com/cli/>`_ installed, you can replicate the CI process with::

    wercker build

Cache invalidator
~~~~~~~~~~~~~~~~

Cache invalidator invalidates capstone's cache by reading Rackspace Identity
events feeds.

Capstone will build a console scripts to start the process::

    capstone-cache-invalidator

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

    [rackspace]
    rackspace_base_url = <rackspace_api_endpoint>
    rackspace_feed_url = <rackspace_feed_endpoint>
    polling_period = <feed_polling_period>

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

Docker
------

Docker image can be built using ``build_docker.sh`` in the deploy directory.
The Docker image is tagged with the git sha revision and latest tag.  The created
image can then be run using docker-compose.  The ``docker-compose.yml`` file
exposes the following environment variables: SERVICE_USER_NAME,
SERVICE_USER_PASSWORD, RACKSPACE_BASE_URL.

Create the docker image and run it with the following commands::

    cd deploy
    ./build_docker.sh
    docker-compose up



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

