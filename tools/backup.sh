#!/bin/sh
set -eu
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
BACKUP_SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
exec /usr/bin/python3 "$BACKUP_SCRIPT_DIR/backup.py" "$@"
