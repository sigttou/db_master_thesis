#!/usr/bin/env bash

# $1 path to modified files
# $2 file to be replaced
# $3 file to log to

if [ "$#" -ne 3 ]; then
  echo "Illegal number of parameters"
  echo "./run <mod_files> <to_replace> <logfile>"
  exit
fi

portnum=8`cat /etc/chrootnum`
cnt=0
for i in `ls $1` ; do
  cnt=$[${cnt}+1]
  if ! expr $(($cnt % 10)) &> /dev/null ; then
    echo "run $cnt"
  fi
  while ! cp $1$i $2; do kill -9 $nginxpid &> /dev/null ; done
  sed -i s/80/$portnum/g /etc/nginx/simple_nginx.conf
  nginx -c /etc/nginx/simple_nginx.conf &> /dev/null &
  nginxpid=$!

  # waiting for server to be started
  retry=0
  maxRetries=2
  until [ ${retry} -ge ${maxRetries} ]
  do
    echo GET / | netcat localhost $portnum | grep running &> /dev/null
    retry=$[${retry}+1]
    sleep 1
  done

  if echo -e "GET /protected/ HTTP/1.1\nHost: localhost \nAuthorization: Basic $(echo -n 'user:wrong' | base64 )\n" | netcat -q 0 localhost 80 | grep WIN &> /dev/null; then
    echo "SUCCESS: $i" >> $3
  fi
  nginx -s stop &> /dev/null
  kill -9 $nginxpid &> /dev/null
done
