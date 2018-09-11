#!/usr/bin/env bash

pin_path=$(dirname "$0")
old_path=$PWD

nginx -c /etc/nginx/simple_nginx.conf &

sleep 2

cd $pin_path
./run_pid.sh $old_path/msc_test.out `pgrep nginx` &

sleep 2
curl -u user:wrong http://localhost/protected/ &> /dev/null

nginx -s stop

sleep 1
while kill -0 `pgrep nginx` 2> /dev/null; do sleep 1; done;

# ../../scripts/elf_structure_flips/add_structures.py $old_path/msc_test.out
grep -vE "libc|libpthread|libnss|ld-linux|libnsl|libdl|libz|vdso" $old_path/msc_test.out > tmp.out
mv tmp.out $old_path/msc_test.out
sort -t "-" -k2 -o $old_path/msc_test.out $old_path/msc_test.out
cd $old_path
