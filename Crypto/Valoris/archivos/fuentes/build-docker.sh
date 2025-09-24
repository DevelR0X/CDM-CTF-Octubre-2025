#!/bin/bash
NAME="crypto_valoris"
docker rm -f $NAME
docker build --tag=$NAME . && \
docker run -e GZCTF_FLAG="CDM{4n07h3r_435_3cb_m155u5...}" -p 1337:1337 --rm --name=$NAME --detach $NAME