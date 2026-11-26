#!/usr/bin/env bash
# The check CI runs on the pull request.
[[ $(bash add.sh 2 3) == 5 ]] || { echo "FAIL: add.sh 2 3 should print 5"; exit 1; }
echo "PASS"
