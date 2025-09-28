#!/bin/bash
NAME="misc_qguess"
docker rm -f $NAME
docker build --tag=$NAME . && \
docker run -e GZCTF_FLAG="CDM{br34k1ng_qu4n7um_5up3rp051710n_f0r_d373rm1n1st1c_0u7pu7!}" -p 1337:1337 --rm --name=$NAME --detach $NAME