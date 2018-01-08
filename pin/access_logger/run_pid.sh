#!/usr/bin/env bash

ROOT=/home/user/build/pin
tmp=`ls | grep cpp`
NAME=${tmp%.cpp}
out=$(basename $2).out
echo $out
make PIN_ROOT=$ROOT obj-intel64/$NAME.so && /home/user/.local/bin/pin -pid $1 -t obj-intel64/$NAME.so -o $out
