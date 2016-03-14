#!/bin/bash

wercker build --commit capstone --tag base
docker build -t capstone:latest -t capstone:$(git rev-parse --short HEAD) .
