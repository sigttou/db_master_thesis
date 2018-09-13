#!/bin/busybox sh

#!!!! /srv/chroot/stretch/etc/login.defs !!!! set LOGIN_RETRIES to 0

# $1 path to modified files
# $2 file to be replaced
# $3 file to log to
# $4 folder to save successfull files to

cnt=0
for i in `ls $1` ; do
  cp $1$i $2
  if passh -P "\$ \{0,1\}$" -p "busybox echo HI\`busybox whoami\`;logout" passh -p wrong passh -P "login: \{0,1\}$" -p user /bin/login | busybox grep HIuser > /dev/null 2>&1; then
    echo "SUCCESS: $i - $2" >> $3
    cp $1$i $4$i
  fi
done
