#!/usr/bin/env bash

# simple shell script to diff between commits of this thesis

# $1 ... commit to diff

if [ "$#" -ne 1 ]; then
  echo "Usage: ./diff_commit.sh commit"
  echo "Generates latexdiff between current state and given commit"
  exit 1
fi

for file in `ls | grep "\.tex" | grep -v "main"`; do
  git show $1:./$file > commit_$file
  mv $file orig_$file
  latexdiff commit_$file orig_$file > $file
  rm commit_$file
done

make pdf
cp $(ls `date --iso-8601`_*.pdf | grep -v "diff") `date --iso-8601`_diff.pdf

for file in `ls | grep "\.tex" | grep -v "main" | grep -v "orig_"` ; do
  mv orig_$file $file
done

make pdf
