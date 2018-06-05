#!/usr/bin/env bash

# $1 = path to chroots
# $2 = folder to modified files
# $3 = file to be replaced

cmd_file=run_sudo_chroot.sh
modified_inside="/media/flips"

for i in $1* ; do
  echo $i
  cp $cmd_file $i/
  mkdir -p $i$modified_inside
  mount --bind $2 $i$modified_inside
  echo -e "./$cmd_file $modified_inside/ $3" | chroot $i
done

