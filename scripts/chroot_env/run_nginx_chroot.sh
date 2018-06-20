#!/usr/bin/env bash

# $1 path to modified files
# $2 file to be replaced
# $3 file to log to
portnum=8`cat /etc/chrootnum`
cnt=0
for i in `ls $1` ; do
  cp $1$i $2
  sed -i s/80/$portnum/g /etc/nginx/simple_nginx.conf
  nginx -c /etc/nginx/simple_nginx.conf &
  if curl --silent -u user:wrong localhost:$portnum/protected/ | grep WIN >& /dev/null; then 
    echo "SUCCESS: $i" >> $3
  fi
  nginx -s stop
done
