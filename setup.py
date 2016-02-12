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
from setuptools import setup


HERE = os.path.dirname(__file__)


def slurp(filename):
    with open(os.path.join(HERE, filename)) as f:
        return f.read()


def read_requirements(filename):
    return filter(None, (l.strip() for l in slurp(filename).splitlines()))


setup(
    name='capstone',
    version='0.1',
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
        'keystone.token.provider': [
            'capstone = capstone.token_provider:Provider',
        ],
    },
    install_requires=read_requirements('requirements.txt'),
    tests_require=read_requirements('test-requirements.txt')
)
