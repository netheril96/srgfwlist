#!/bin/bash
git pull --rebase;
cd "$(dirname "$(realpath "$0")")";
python3 ./gensrrules.py;
git add fullrules.*;
git commit -m 'Rebuild full rules';
git push;
