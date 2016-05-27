#!/bin/bash
set -e

# Ensure we're running on our target platform
lsb_release -a | grep '14.04'

# Install apt requirements
sed "s@archive.ubuntu.com@mirror.rackspace.com@" \
    -i /etc/apt/sources.list
apt update
# apt-transport-https is only required due to
# https://bugs.launchpad.net/openstack-ansible/+bug/1547541
apt install -V -y \
    build-essential \
    apt-transport-https \
    curl \
    git-core \
    libffi-dev \
    libssl-dev \
    python-dev

# Install modern pip
curl https://bootstrap.pypa.io/get-pip.py \
    -o /tmp/get-pip.py
python /tmp/get-pip.py
rm /tmp/get-pip.py

# Install pip requirements
pip install \
    "ansible<2" \
    tox

# Install ansible galaxy requirements
ansible-galaxy install -r deploy/ansible-role-requirements.yml
