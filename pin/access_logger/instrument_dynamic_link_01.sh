#!/usr/bin/env bash

pin_path=$(dirname "$0")
old_path=$PWD

cd $pin_path
echo 1 | ./run.sh $old_path/msc_test.out /usr/bin/dynamic_link_01

grep "dynamic_link_01\|libsucc" $old_path/msc_test.out > /tmp/tmplog
mv /tmp/tmplog $old_path/msc_test.out

../../scripts/elf_structure_flips/add_structures.py $old_path/msc_test.out
cd $old_path
