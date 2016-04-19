#!/bin/bash

wercker build --wercker-yml wercker-deploy.yml --commit capstone --tag base
docker build -t "capstone:latest" -t "capstone:$(git rev-parse --short HEAD)" deploy
