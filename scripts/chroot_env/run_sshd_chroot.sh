#!/bin/busybox sh

# $1 path to modified files
# $2 file to be replaced
# $3 file to log to
# $4 folder to save successfull files to

if [ "$#" -ne 4 ]; then
  echo "Illegal number of parameters"
  echo "./run <mod_files> <to_replace> <logfile> <logfolder>"
  exit
fi

portnum=222`cat /etc/chrootnum`
for i in `ls $1` ; do
  while ! cp $1$i $2; do kill -9 $sshdpid &> /dev/null ; done
  sshd -f /etc/ssh/sshd_test_config -p $portnum 
  sshdpid=`pgrep -f "sshd_test_config -p $portnum"` 

  # waiting for server to be started
  sleep 1

  if sshpass -p wrong ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p $portnum localhost "true" &> /dev/null; then
    echo "SUCCESS: $i - $2" >> $3
    cp $1$i $4$i
  fi
  kill -9 $sshdpid &> /dev/null
done
