#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
  echo "Illegal number of parameters"
  exit
fi

cd $1
sudo chown root:root *; sudo chmod +x * ; sudo chmod u+s * ;
cnt=0
for i in *; do
  if ! (($cnt % 10)); then
    echo $cnt
  fi
  timeout -s 9 0.1 ./$i echo win 2>&1 | grep win
  cnt=$((cnt+1))
done
