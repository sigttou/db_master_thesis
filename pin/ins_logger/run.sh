#!/usr/bin/env bash

ROOT=/home/user/build/pin
tmp=`ls | grep cpp`
NAME=${tmp%.cpp}
call=$@
out=${@: -1}
make PIN_ROOT=$ROOT obj-intel64/$NAME.so && pin -t obj-intel64/$NAME.so -- $call
mv $NAME.out $out.out
