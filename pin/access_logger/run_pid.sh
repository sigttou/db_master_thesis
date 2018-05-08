#!/usr/bin/env bash

ROOT=/home/user/build/pin
tmp=`ls | grep cpp`
NAME=${tmp%.cpp}
out=$(basename $2).out
echo $out
echo $1
make PIN_ROOT=$ROOT obj-intel64/$NAME.so && /home/user/.local/bin/pin -xyzzy -mesgon log_win -pid $1 -t obj-intel64/$NAME.so -o $out
