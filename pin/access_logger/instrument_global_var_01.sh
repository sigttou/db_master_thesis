#!/usr/bin/env bash

pin_path=$(dirname "$0")
old_path=$PWD

cd $pin_path
echo 1 | ./run.sh $old_path/msc_test.out /usr/bin/global_var_01
cd $old_path

grep global_var_01 $old_path/msc_test.out > /tmp/tmplog
mv /tmp/tmplog $old_path/msc_test.out
