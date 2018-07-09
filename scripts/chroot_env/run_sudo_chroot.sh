#!/bin/busybox sh

# $1 path to modified files
# $2 file to be replaced
# $3 file to log to
# $4 folder to save successfull files to

cnt=0
for i in `ls $1` ; do
  cp $1$i $2
  chmod u+s /usr/bin/sudo
  if su -c "echo wrong | timeout -s 9 0.1 sudo -S whoami 2>&1 | grep root" - user > /dev/null 2>&1; then
    if su -c "echo wrong | sudo -S grep win /checkfile" - user > /dev/null 2>&1 ; then
      echo "SUCCESS: $i - $2" >> $3
      cp $1$i $4$i
    fi
  fi
done
