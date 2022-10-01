#!/bin/bash
set -e;
set -x;
cd "$(dirname "$(realpath "$0")")";
git pull --rebase;
python3 ./gensrrules.py;
STATUS_MSG=$(git status);
if [[ $STATUS_MSG == *'Changes not staged for commit'* ]]
then
  git add fullrules.*;
  git commit -m 'Rebuild full rules';
  git push;
fi
