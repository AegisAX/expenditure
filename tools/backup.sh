#!/bin/sh
set -eu
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
cd /home/whitehat/expenditure_dev
exec /usr/bin/python3 tools/backup.py
