#!/usr/bin/env bash

# simple shell script to diff between commits of this thesis

# $1 ... commit a for latexdiff
# $2 ... commit b for latexdiff

if [ "$#" -ne 2 ]; then
  echo "Usage: ./diff_commit.sh commit_a commit_b"
  echo "Generates latexdiff between to commits !!!! KILLS YOUR CURRENT FILES !!!!"
  exit 1
fi

for file in `ls | grep "\.tex" | grep -v "main"`; do
  git show $1:./$file > a_$file
  git show $2:./$file > b_$file
  latexdiff a_$file b_$file > $file
  rm a_$file
  rm b_$file
done

make pdf

for file in `ls | grep "\.tex" | grep -v "main"`; do
  git checkout $file
done
