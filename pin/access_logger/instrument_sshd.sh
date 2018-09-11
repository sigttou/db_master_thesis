#!/usr/bin/env bash

pin_path=$(dirname "$0")
old_path=$PWD

/usr/sbin/sshd -f /home/user/MSC/db_master_thesis/configs/sshd/sshd_config -p 2222

sleep 2

cd $pin_path
./run_pid.sh $old_path/msc_test.out `pgrep -f "config -p 2222"` &

sleep 2

sshpass -p wrong ssh -p 2222 localhost 2> /dev/null

kill `pgrep -f "config -p 2222"`

sleep 1

while kill -0 `pgrep -f "sshd_config -p 2222"` 2> /dev/null; do sleep 1; done;

grep -vE "libc|libpthread|libnss|ld-linux|libnsl|libdl|libz|vdso" $old_path/msc_test.out > tmp.out
mv tmp.out $old_path/msc_test.out
sort -t "-" -k2 -o $old_path/msc_test.out $old_path/msc_test.out
cd $old_path
