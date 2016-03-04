Deploying Capstone
==================

.. image:: https://app.wercker.com/status/e6feb4196b5f4849659de6585039007b/s/master
   :target: https://app.wercker.com/#applications/56cd0b9aab54a673190541dc

Deployment tooling for `Capstone <https://github.com/rackerlabs/capstone>`_.

Usage
-----

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

This account is provided by Rackspace. Once the ``capstone.conf`` and
``inventory`` files are in place we're ready to deploy::

    ansible-playbook -i inventory deploy.yml
