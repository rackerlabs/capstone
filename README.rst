Capstone
========

.. image:: https://app.wercker.com/status/409d943a74ce1d67a566d80ecbacd5fd/s/master
   :target: https://app.wercker.com/#applications/56bd3ba8239090c836084417

Entry points for `OpenStack Keystone <https://github.com/openstack/keystone>`_
in the Rackspace Public Cloud.

High-level architecture
-----------------------

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

Design priorities
-----------------

1. **Reliability, durability, and uptime.**

   - v3 should *never* impact the reliability of v2 in any way.

   - v3 should regress gracefully when v2 has outages, downtime, or
     inconsistent responses.

   - If it's not comprehensively tested, then it's not supported.

2. **Defcore-compliant.**

   - v3 must maintain complete Defcore compliance.

3. **Ease of deployment & operations.**

   - Deploying v3 should not impact v2 at all, or vice versa.

   - It should be trivial to vertically & horizontally scale as necessary.

   - We should provide first class metrics & insights at runtime.

4. **Seamless experience.**

   - v2 is the single source of truth for authentication. Only v3-specific
     authorization may live in Keystone.

5. **Performance.**

   - v3 should add minimal response time overhead to v2.

Use cases
---------

1. **Create a token.** This is required for defcore compliance. The returned
   token must work with existing OpenStack services, which currently use v2 for
   token validation.

   The following authentication claims are expected to be supported by the v3
   API:

   - `token`

   - `password` + `user_id`

   - `password` + `user_name` + `user_domain_id`

   - `password` + `user_name` + `user_domain_name`

   The following authorization scopes are supported by the v3 API:

   - Unscoped, or automatically scoped to a preferred project

   - Project-scoped: `project_id`

   - Project-scoped: `project_name` + `project_domain_id`

   - Project-scoped: `project_name` + `project_domain_name`

   - Domain-scoped: `domain_id`

   - Domain-scoped: `domain_name`

2. **Validate a token.** Rackspace public cloud should use v3 internally, and
   the first step is to allow them to validate user tokens against Keystone.

3. **User account management.** Users should be able to update their own
   password and change their username with the same user experience as the v2
   API.

4. **Delegation.** Users should be able to use v3 to delegate authorization to
   each other (trusts or otherwise).

v3 ⟷ v2 attribute mapping
-------------------------

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

Deployment
----------

Deployment tooling lives in a separate repository: `rackerlabs/capstone-deploy
<https://github.com/rackerlabs/capstone-deploy>`_.

Contributing
------------

Useful links:

- `Code reviews
  <https://review.gerrithub.io/#/dashboard/?title=Capstone&Capstone=is:open+project:rackerlabs/capstone&Deployment=is:open+project:rackerlabs/capstone-deploy>`_

- `Issue tracking
  <https://github.com/rackerlabs/capstone/issues>`_

Workflow
~~~~~~~~

The developer workflow mirrors that of OpenStack:

- Clone the repository: ``git clone git@github.com:rackerlabs/capstone.git &&
  cd capstone/``

- Setup git-review: ``pip install --upgrade git-review && git review -s``

- Create a branch to work from, or go untracked: ``git checkout HEAD~0``

- Create a commit: ``git commit``.

  A Change-Id will be appended to your commit message to uniquely identify your
  code review.

- Upload it for review: ``git review``.

  You'll get a link to your code review on ``gerrithub.io``. A bot will then
  pull your change, run ``wercker build`` on it to test it, and upload the
  results back to gerrit, setting the `Verified` field to indicate build
  success or failure. If you have a Docker server available, you can run
  ``wercker build`` yourself using the `wercker CLI
  <https://github.com/wercker/wercker>`_.

- Your patch will be peer reviewed.

  If you need to upload a revision of your patch, fetch the latest patchset
  from gerrit using: ``git review -d <change-number>``, where your change
  number is NOT your Change-Id, but instead is 7 digit number in the URL of
  your code review.

- When your patch receives a +2 and is passing tests, it will be automatically
  merged.
