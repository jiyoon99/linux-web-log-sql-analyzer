# Project Agents Override

## Stack

- Python 3.10+
- SQLite
- Optional web dashboard: FastAPI, Uvicorn
- Tests: `unittest`

## Commands

- Install: `pip install -e ".[web]"`
- Dev: `PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli --help`
- Test: `PYTHONPATH=src python3 -m unittest discover -s tests`
- CI: `python -m unittest discover -s tests`
- Build: `python -m build`
- Offline Build: `python -m build --no-isolation` after `pip install build setuptools wheel`
- Ingest sample: `PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli ingest samples/nginx-access.log --db data/test.db`
- Ingest SQL sample: `PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli ingest-sql samples/sql-execution.log --db data/test.db`
- Summary: `PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli summary --db data/test.db`
- SQL summary: `PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli sql-summary --db data/test.db`
- Docker: `docker compose up --build`
- E2E: Not configured

## Architecture Notes

- `parser.py` parses access log lines and must not depend on SQLite or FastAPI.
- `database.py` owns schema creation and inserts.
- `analyzer.py` owns SQL aggregate queries.
- `sql_parser.py` parses SQL execution logs and MySQL slow query logs.
- `cli.py` is the command entrypoint.
- `web.py` exposes the optional FastAPI dashboard.

## Quality Gates

- Parser tests must cover valid combined logs and malformed lines.
- Database tests must ingest fixture logs and verify aggregate counts.
- SQL parser tests must cover simple execution logs and MySQL slow query blocks.
- Any user-controlled value shown in HTML must be escaped.
- SQL queries must use bound parameters for user input.
- URL query values for token/password/api_key/session-like keys must remain masked.

## Project-Specific Rules

- Keep the MVP dependency-light; do not add heavy analytics frameworks without a concrete need.
- Preserve parse failures as rows instead of silently dropping them.
- Do not expose raw secret-bearing log values in UI or export output.
