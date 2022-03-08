#!/bin/bash
set -e;
set -x;
cd "$(dirname "$(realpath "$0")")";
git pull --rebase;
python3 ./gensrrules.py;
git add fullrules.*;
git commit -m 'Rebuild full rules';
git push;
