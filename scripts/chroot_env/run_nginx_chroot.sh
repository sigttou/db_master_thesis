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

portnum=8`cat /etc/chrootnum`
sed -i s/80/$portnum/g /etc/nginx/simple_nginx.conf
cnt=0
for i in `ls $1` ; do
  cnt=$[${cnt}+1]
  if ! expr $(($cnt % 10)) &> /dev/null ; then
    echo "run $cnt"
  fi
  while ! cp $1$i $2; do kill -9 $nginxpid &> /dev/null ; done
  nginx -c /etc/nginx/simple_nginx.conf &> /dev/null &
  nginxpid=$!

  # waiting for server to be started
  retry=0
  maxRetries=2
  until [ ${retry} -ge ${maxRetries} ]
  do
    echo GET / | timeout -s 9 2 netcat localhost $portnum | grep running &> /dev/null
    retry=$[${retry}+1]
    sleep 1
  done

  if echo -e "GET /protected/ HTTP/1.1\nHost: localhost \nAuthorization: Basic $(echo -n 'user:wrong' | base64 )\n" | timeout -s 9 2 netcat -q 0 localhost $portnum | grep WIN &> /dev/null; then
    echo "SUCCESS: $i" >> $3
    cp $1$i $4$i
  fi
  timeout -s 9 2 nginx -s stop &> /dev/null
  kill -9 $nginxpid &> /dev/null
done
