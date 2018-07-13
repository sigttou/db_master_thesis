#!/usr/bin/env bash
# prints diff of $1 and $2

set -e
function finish {
  rm -f tmp_file
  rm -f a_diff.tmp
  rm -f b_diff.tmp
}

if [ "$#" -ne 2 ]; then
  echo "Illegal number of parameters"
  echo "./objdump_diff.sh <file_a> <file_b>"
  exit 1
fi
trap finish EXIT

cp $1 tmp_file
objdump -D tmp_file > a_diff.tmp
cp $2 tmp_file
objdump -D tmp_file > b_diff.tmp

diff -U4 --color a_diff.tmp b_diff.tmp || exit 0
