#!/usr/bin/env bash

cp /usr/bin/sudo /tmp/msc_test
chown root:root /tmp/msc_test
chmod +x /tmp/msc_test
chmod u+s /tmp/msc_test

su - user -c "echo wrong | /tmp/msc_test -S whoami" &> /dev/null &
sleep 1
./run_pid.sh msc_test `pgrep msc_test`

while kill -0 `pgrep msc_test` 2> /dev/null; do sleep 1; done;
