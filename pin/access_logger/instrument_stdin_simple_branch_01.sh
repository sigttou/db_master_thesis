#!/usr/bin/env bash

pin_path=$(dirname "$0")
old_path=$PWD

cd $pin_path
echo 1 | ./run.sh $old_path/msc_test.out /usr/bin/stdin_simple_branch_01
cd $old_path