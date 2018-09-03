#!/usr/bin/env bash

# simple shell script to diff between commits of this thesis

# $1 ... commit a for latexdiff
# $2 ... commit b for latexdiff

if [ "$#" -ne 2 ]; then
  echo "Usage: ./diff_commit.sh commit_a commit_b"
  echo "Generates diff_commita_commitb.pdf in the current folder."
  exit 1
fi

