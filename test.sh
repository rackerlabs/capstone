#!/bin/bash
set -e

# Ensure we're running on our target platform
lsb_release -a | grep '14.04'

cd deploy

# Populate inventory file
export ANSIBLE_INVENTORY=${INVENTORY:-inventory_localhost}

# Syntax check ansible playbook
ansible-playbook \
    --syntax-check \
    -i $ANSIBLE_INVENTORY \
    -e @local_vars.yml \
    deploy.yml

# Run playbook
ansible-playbook \
    -i $ANSIBLE_INVENTORY \
    -e @local_vars.yml \
    deploy.yml

# Ensure keystone is running
curl \
    --cacert /etc/ssl/certs/keystone.pem \
    https://localhost:8443/

# Deploy mock v2 service
ansible-playbook \
    -i $ANSIBLE_INVENTORY \
    deploy_mock_v2.yml

# Setup integration testing requirements
ansible-playbook \
    -i $ANSIBLE_INVENTORY \
    -e @testing_vars.yml \
    setup_integration_test_host.yml

# Run tests
cd -
tox
