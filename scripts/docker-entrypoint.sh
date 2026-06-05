#!/bin/sh
set -eu

DB_PATH="${WEB_LOG_SQL_DB:-data/dashboard.db}"

if [ ! -f "$DB_PATH" ]; then
  mkdir -p "$(dirname "$DB_PATH")"
  web-log-sql ingest samples/nginx-access.log --db "$DB_PATH"
  web-log-sql ingest-sql samples/sql-execution.log --db "$DB_PATH"
  web-log-sql ingest-sql samples/mysql-slow.log --db "$DB_PATH"
fi

exec "$@"
