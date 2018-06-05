#!/usr/bin/env bash

# $1 path to modified files
# $2 file to be replaced

cnt=0
for i in `ls $1` ; do
  cp $1$i $2
  su -c "echo wrong | timeout -s 9 0.1 sudo -S whoami 2>&1 | grep root" - user
done
