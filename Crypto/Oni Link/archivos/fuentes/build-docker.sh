#!/bin/bash
NAME="crypto_oni_link"
docker rm -f $NAME
docker build --tag=$NAME . && \
docker run -e GZCTF_FLAG="CDM{ch4ch4_d4nc3_w17h_kn0wn_pl4int3xt_4774ck!}" -p 1337:1337 --rm --name=$NAME --detach $NAME