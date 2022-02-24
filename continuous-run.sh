#!/bin/bash
set -e;
set -x;
while :
do
  git pull --rebase
  python3 ./gensrrules.py
  git add fullrules.*
  git commit -m 'Rebuild full rules'
  git push
  sleep 3599
done