#!/usr/bin/env python

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
import subprocess

import setuptools


VERSION = '0.1'
HERE = os.path.dirname(__file__)


def get_version():
    def git_sha(refspec):
        output = subprocess.check_output(['git', 'show-ref', refspec])
        return output.split(' ')[0]

    try:
        tagged_sha = git_sha(VERSION)
        current_sha = git_sha('HEAD')
        if tagged_sha != current_sha:
            return '%s+%s' % (VERSION, current_sha.strip()[:7])
        return VERSION
    except subprocess.CalledProcessError:
        return VERSION


def slurp(filename):
    with open(os.path.join(HERE, filename)) as f:
        return f.read()


def read_requirements(filename):
    return filter(None, (l.strip() for l in slurp(filename).splitlines()))


setuptools.setup(
    name='capstone',
    version=get_version(),
    description='Keysone Drivers & Plugins for Rackspace',
    long_description=slurp('README.rst'),
    author='The Rackspace Identity Team',
    url='https://github.com/rackerlabs/capstone',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
    ],
    license='Apache 2.0',
    packages=['capstone'],
    entry_points={
        'keystone.auth.password': [
            'capstone = capstone.auth_plugin:Password',
        ],
        'keystone.auth.token': [
            'capstone = capstone.auth_plugin:Token',
        ],
        'keystone.token.provider': [
            'capstone = capstone.token_provider:Provider',
        ],
        'keystone.revoke': [
            'capstone = capstone.custom_revoke_driver:Revoke',
        ],
        'console_scripts': [
            'capstone-cache-invalidator = capstone.cache_invalidator:main'
        ],
    },
    install_requires=read_requirements('requirements.txt')
)
