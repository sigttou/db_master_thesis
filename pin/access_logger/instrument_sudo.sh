#!/usr/bin/env bash

pin_path=$(dirname "$0")
old_path=$PWD
cp /usr/bin/sudo /tmp/msc_test
chown root:root /tmp/msc_test
chmod +x /tmp/msc_test
chmod u+s /tmp/msc_test

su - user -c "echo wrong | /tmp/msc_test -S whoami" &> /dev/null &
sleep 1
cd $pin_path
./run_pid.sh $old_path/msc_test.out `pgrep msc_test`
cd $old_path
while kill -0 `pgrep msc_test` 2> /dev/null; do sleep 1; done;