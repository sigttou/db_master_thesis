#!/usr/bin/env bash

ROOT=/opt/pin/pin
tmp=`ls | grep cpp`
NAME=${tmp%.cpp}
call=$@
out=$(basename $1).out
make PIN_ROOT=$ROOT obj-intel64/$NAME.so && $ROOT/pin -t obj-intel64/$NAME.so -o $out -- $call
