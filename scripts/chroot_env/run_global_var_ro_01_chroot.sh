#!/usr/bin/env bash

# $1 path to modified files
# $2 file to be replaced
# $3 file to log to
# $4 folder to save successfull files to

if [ "$#" -ne 4 ]; then
  echo "Illegal number of parameters"
  echo "./run <mod_files> <to_replace> <logfile> <logfolder>"
  exit
fi

cnt=0
for i in `ls $1` ; do
  cnt=$[${cnt}+1]
  if ! expr $(($cnt % 10)) &> /dev/null ; then
    echo "run $cnt"
  fi
  cp $1$i $2
  chmod +x /usr/bin/global_var_ro_01
  if echo 1 | timeout -s 9 2 /usr/bin/global_var_ro_01 | grep success &> /dev/null; then
    echo "SUCCESS: $i" >> $3
    cp $1$i $4$i
  fi

done
