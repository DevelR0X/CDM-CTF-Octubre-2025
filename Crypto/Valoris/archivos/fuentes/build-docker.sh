#!/bin/bash
NAME="crypto_valoris"
docker rm -f $NAME
docker build --tag=$NAME . && \
docker run -p 1337:1337 --rm --name=$NAME --detach $NAME