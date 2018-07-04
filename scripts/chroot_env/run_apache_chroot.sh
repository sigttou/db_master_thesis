#!/usr/bin/env bash

# $1 path to modified files
# $2 file to be replaced
# $3 file to log to
# $4 folder to save successfull files to

cnt=0
for i in `ls $1` ; do
  cp $1$i $2
  apache2ctl start
  if curl --silent -u user:wrong localhost/protected/ | grep WIN >& /dev/null; then 
    echo "SUCCESS: $i" >> $3
    cp $1$i $4$i
  fi
  apache2ctl stop
done
