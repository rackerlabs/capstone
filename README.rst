Capstone
========

.. image:: https://app.wercker.com/status/409d943a74ce1d67a566d80ecbacd5fd/m
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

2. **Validate a token.** Rackspace public cloud should use v3 internally, and
   the first step is to allow them to validate user tokens against Keystone.

3. **User account management.** Users should be able to update their own
   password and change their username with the same user experience as the v2
   API.

4. **Delegation.** Users should be able to use v3 to delegate authorization to
   each other (trusts or otherwise).
