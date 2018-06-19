#!/usr/bin/env bash

pin_path=$(dirname "$0")
old_path=$PWD

sudo chroot /var/chroot/bionic_templ/ apachectl start

sleep 2
cd $pin_path
for pid in `pgrep apache2`
do
  ./run_pid.sh $old_path/msc_test_$pid.out $pid &
done
cd $old_path

sleep 2
curl -u user:wrong http://localhost/protected/ &> /dev/null

sudo chroot /var/chroot/bionic_templ/ apachectl stop
while kill -0 `pgrep apache2` 2> /dev/null; do sleep 1; done;

cat msc_test_*.out > msc_test.out
rm msc_test_*.out
