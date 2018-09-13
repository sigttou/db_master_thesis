#!/usr/bin/env bash

pin_path=$(dirname "$0")
old_path=$PWD
cp /bin/login /tmp/msc_test
chown root:root /tmp/msc_test
chmod +x /tmp/msc_test

passh -p wrong passh -P "login: \{0,1\}$" -p user /tmp/msc_test &> /dev/null &
sleep 1

cd $pin_path
./run_pid.sh $old_path/msc_test.out `pgrep msc_test`
while kill -0 `pgrep msc_test` 2> /dev/null; do sleep 1; done

grep -vE "vdso" $old_path/msc_test.out > tmp.out
mv tmp.out $old_path/msc_test.out
#../../scripts/elf_structure_flips/add_structures.py $old_path/msc_test.out
sort -t "-" -k2 -o $old_path/msc_test.out $old_path/msc_test.out
sed -i s+/tmp/msc_test+/bin/login+g $old_path/msc_test.out
cd $old_path
