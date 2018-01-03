#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
  echo "Illegal number of parameters"
  exit
fi

cd $1
sudo chown root:root *; sudo chmod +x * ; sudo chmod u+s * ;
for i in *; do
  timeout 0.1 ./$i -i 2>&1; 
done
