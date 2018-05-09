#!/usr/bin/env bash

ROOT=/opt/pin/pin
tmp=`ls | grep cpp`
NAME=${tmp%.cpp}
out=$(basename $1).out
echo $out
echo $2
make PIN_ROOT=$ROOT obj-intel64/$NAME.so 
$ROOT/pin -xyzzy -mesgon log_win -pid $2 -t obj-intel64/$NAME.so -o $out
