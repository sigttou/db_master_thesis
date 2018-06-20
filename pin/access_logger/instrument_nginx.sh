#!/usr/bin/env bash

pin_path=$(dirname "$0")
old_path=$PWD

nginx -c /etc/nginx/simple_nginx.conf &

sleep 2

cd $pin_path
./run_pid.sh $old_path/msc_test.out `pgrep nginx` &
cd $old_path

sleep 2
curl -u user:wrong http://localhost/protected/ &> /dev/null

nginx -s stop

sleep 1

while kill -0 `pgrep nginx` 2> /dev/null; do sleep 1; done;
