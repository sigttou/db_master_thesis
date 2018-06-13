#!/usr/bin/env bash

if [ "$#" -ne 5 ]; then
  echo "Illegal number of parameters - this should only be called from run_tests.sh"
  echo "./worker.sh <chroot_to_run_in> <flips_to_test> <file_to_run> <log_file> <file_to_replace>"
  exit 1
fi

modified_inside="/media/flips"
run_chroot=$1
run_flips=$2
cmd_file=$3
log_file=$4
file_to_replace=$5

cp $cmd_file $run_chroot/ || { echo 'cp failed' ; exit 1; }
if [ ! -e "$run_chroot$modified_inside" ]; then
  mkdir -p $run_chroot$modified_inside || { echo 'mkdir failed' ; exit 1; }
  mount --bind $run_flips $run_chroot$modified_inside || { echo 'mount failed' ; exit 1; }
fi
echo -e "./$cmd_file $modified_inside/ $file_to_replace $log_file" | chroot $run_chroot
umount $run_chroot$modified_inside
rmdir $run_chroot$modified_inside
