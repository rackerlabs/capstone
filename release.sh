#!/bin/bash

# let's build everything in a temporary location that is cleaned every run
WHEEL_DIR=/tmp/wheelhouse
BUILD_LOCATION=/tmp/capstone-builder
rm -rf $WHEEL_DIR
rm -rf $BUILD_LOCATION

virtualenv /tmp/builder
source /tmp/builder/bin/activate
pip install wheel

# build the wheels using requirements and put the resulting build in
# /tmp/wheelhouse/
pip wheel --timeout 120 \
    --wheel-dir $WHEEL_DIR \
    --requirement requirements.txt \
    --build $BUILD_LOCATION \
    .

deactivate
