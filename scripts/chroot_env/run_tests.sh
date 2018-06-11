#!/usr/bin/env bash

# $1 = path to chroots
# $2 = folder to modified files
# $3 = file to be replaced

cmd_file=run_sudo_chroot.sh
modified_inside="/media/flips"

worker () {
  local run_chroot=$1
  local run_path=$2
  local run_file=$3
  cp $cmd_file $run_chroot/ || { echo 'cp failed' ; exit 1; }
  mkdir -p $run_chroot$modified_inside || { echo 'mkdir failed' ; exit 1; }
  mount --bind $run_path $run_chroot$modified_inside || { echo 'mount failed' ; exit 1; }
  echo -e "./$cmd_file $modified_inside/ $run_file" | chroot $run_chroot
}

if [ "$#" -ne 3 ]; then
  echo "Illegal number of parameters"
  echo "./run_tests.sh <chroots_path> <modified_files> <file_to_replace>"
  exit 1
fi

for i in $1* ; do worker "$i" "$2" "$3" & done

echo DONE!
