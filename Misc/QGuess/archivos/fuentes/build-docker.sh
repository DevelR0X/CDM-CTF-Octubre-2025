#!/bin/bash
NAME="misc_qguess"
docker rm -f $NAME
docker build --tag=$NAME . && \
docker run -e GZCTF_FLAG="CDM{qu4n7uM_3n74nGl3m3n7_15_r34l?!}" -p 1337:1337 --rm --name=$NAME --detach $NAME