#!/usr/bin/env bash

ROOT=/opt/pin/pin
tmp=`ls | grep cpp`
NAME=${tmp%.cpp}
call="${*:2}"
out=$1
make PIN_ROOT=$ROOT obj-intel64/$NAME.so && $ROOT/pin -t obj-intel64/$NAME.so -o $out -- $call
