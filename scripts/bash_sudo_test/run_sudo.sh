#!/usr/bin/env bash

task()
{
  echo wrong | timeout -s 9 0.1 ./$1 -S echo win 2>&1 | grep win
}

if [ "$#" -ne 1 ]; then
  echo "Illegal number of parameters"
  exit
fi

cd $1
sudo -- sh -c "chown root:root *; chmod +x * ; chmod u+s *"
cnt=0
for i in *; do
  if ! (($cnt % 100)); then
    echo $cnt
  fi
  task "$i" &
  cnt=$((cnt+1))
done
