#!/bin/bash

docker build -f Dockerfile.bkp -t django-test-workshop .
docker run -it --rm -p 8080:8080 django-test-workshop
