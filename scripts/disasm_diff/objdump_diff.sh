#!/usr/bin/env bash

# prints diff of $1 and $2

if [ "$#" -ne 2 ]; then
  echo "Illegal number of parameters"
  echo "./objdump_diff.sh <file_a> <file_b>"
  exit 1
fi

cp $1 tmp_file
a=$(objdump -D tmp_file)
cp $2 tmp_file
b=$(objdump -D tmp_file)

diff -U4 --color <(echo "$a") <(echo "$b")

rm tmp_file
