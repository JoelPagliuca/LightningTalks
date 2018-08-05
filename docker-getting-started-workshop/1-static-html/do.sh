#!/bin/bash

docker run --rm -d -p 7070:80 -v $(pwd)/test.html:/usr/share/nginx/html/index.html nginx
