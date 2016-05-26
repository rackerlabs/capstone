#!/bin/bash
set -e

# NOTE(lbragstad): This script assumes that you've already run `bash
# bootstrap.sh`

# Ensure we're running on our target platform
lsb_release -a | grep '14.04'

# Install requirements for building capstone and it's dependencies.
sudo apt-get install -V -y \
    libldap2-dev \
    libsasl2-dev \
    libxslt1.1 \
    libxslt1-dev

# Install virtualenv so we can install capstone and everything it requires
# into a virtualenv
pip install -U virtualenv

# Create a workspace for building and get ready to build
mkdir -p /tmp/working
mkdir -p /tmp/built-venvs
cd /tmp/working

cat > requirements.txt <<EOF
argparse
capstone
keystone
keystonemiddleware
oslo.log
oslo.middleware
pbr
pycrypto
python-keystoneclient==2.3.1
python-memcached
python-openstackclient
repoze.lru
EOF

cat > constraints.txt <<EOF
git+https://git.openstack.org/openstack/keystone@stable/mitaka#egg=keystone
git+https://github.com/rackerlabs/capstone@master#egg=capstone
EOF

branch_sha="$(git ls-remote https://github.com/rackerlabs/capstone master | awk '{print $1}')"
release_tag="${branch_sha:0:7}"

if [ -d "capstone-${release_tag}" ]; then
  rm -rf "capstone-${release_tag}"
fi

# Create the virtualenv, including the sha from capstone.
virtualenv --always-copy --never-download "capstone-${release_tag}"

# Activate the virtualenv and install everything.
source "capstone-${release_tag}/bin/activate"
pip install -c constraints.txt -r requirements.txt
deactivate

find "capstone-${release_tag}" -type f -name '*.pyc' -delete

# Pack up the virtualenv we just built and store a checksum. The checksum is
# needed by the os_keystone role to verify the virtualenv at install time.
tar czf "/tmp/built-venvs/capstone-${release_tag}.tgz" -C "capstone-${release_tag}" .
md5sum "/tmp/built-venvs/capstone-${release_tag}.tgz" | awk '{print $1}' > "/tmp/built-venvs/capstone-${release_tag}.checksum"

# Clean up the virtualenv.
rm -rf "capstone-${release_tag}"
