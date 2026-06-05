# Team Review

Date: 2026-06-05

## Scope

This review covers the current MVP of `linux-web-log-sql-analyzer`: CLI, parsers, SQLite storage, analyzer queries, optional FastAPI dashboard, tests, CI, and Docker runtime.

## Team Contributions

| Role | Member | What They Did |
|---|---|---|
| PM / Team Lead | Codex | Classified the work, selected roles, ran baseline tests and sample CLI flows, merged findings into this action plan. |
| Backend Developer | Kepler | Reviewed CLI, parser, analyzer, and database behavior. Found the global `--db` bug, SQL redaction gap, duplicate ingest risk, streaming parser need, and report additions. |
| Security Engineer | Dirac | Reviewed secret handling, SQL injection, XSS, CSV injection, API exposure, Docker runtime posture. Confirmed existing defenses and flagged exposed dashboard/API and SQL redaction gaps. |
| QA Engineer | Beauvoir | Reviewed test coverage and verification gaps. Proposed CLI, FastAPI route, parser edge case, SQL parser, and analyzer filter tests. |
| DevOps Engineer | Jason | Reviewed packaging, CI, Dockerfile, compose, and install reliability. Found the `httpx2` dependency issue, missing Docker smoke test, editable Docker install, and runtime volume concerns. |
| Architect | PM-applied | Checked module boundaries against project rules. Confirmed current boundaries are reasonable and identified the next structural improvements: shared input validation, ingestion policy, and redaction strategy. |
| Database Engineer | PM-applied | Reviewed schema and ingest behavior. Flagged missing duplicate-ingest policy and need for source/line uniqueness or explicit replace/skip modes. |

## Priority Findings

### P0 / Fix First

1. Global `--db` can be ignored depending on CLI argument position.
   - File: `src/linux_web_log_sql_analyzer/cli.py`
   - Impact: `web-log-sql --db custom.db summary` can still use the subcommand default `data/logs.db`.
   - Fix: Avoid duplicate defaults for global and subcommand `--db`, or use `argparse.SUPPRESS` on subcommand defaults.
   - Owner: Backend Developer

2. SQL redaction misses `INSERT (...) VALUES (...)` secrets.
   - File: `src/linux_web_log_sql_analyzer/sanitize.py`
   - Impact: values for columns like `password`, `api_key`, `session_id` can be stored and exposed through API/UI.
   - Fix: Add SQL redaction for positional `INSERT` values or move to a small tokenizer-based redactor.
   - Owner: Security Engineer + Backend Developer

3. `pyproject.toml` has likely bad test dependency `httpx2`.
   - File: `pyproject.toml`
   - Impact: CI/install reliability and unnecessary supply-chain surface.
   - Fix: Replace with `httpx>=0.28.0` if FastAPI route tests are added, otherwise remove the test extra dependency.
   - Owner: DevOps Engineer + QA Engineer

## P1 / Improve Soon

1. Duplicate ingestion is possible.
   - Files: `database.py`, `cli.py`
   - Fix options: add `UNIQUE(source, line_no)` and `INSERT OR IGNORE`, or add explicit `--skip-existing` / `--replace` modes.
   - Owner: Database Engineer + Backend Developer

2. Docker dashboard is exposed on all host interfaces.
   - File: `docker-compose.yml`
   - Fix: use `127.0.0.1:18080:18080` as the default local compose binding, and document production reverse proxy/auth requirements.
   - Owner: Security Engineer + DevOps Engineer

3. FastAPI route integration tests are missing.
   - Files: `tests/test_web.py`, new `tests/test_web_routes.py`
   - Fix: add `/health`, `/api/v1/logs`, `/api/v1/sql-logs`, invalid numeric query, and unknown report tests.
   - Owner: QA Engineer

4. CLI behavior tests are missing.
   - New file: `tests/test_cli.py`
   - Fix: assert exit codes, output strings, DB path behavior, and CSV injection escaping.
   - Owner: QA Engineer + Backend Developer

5. SQL parser loads whole SQL log files into memory.
   - File: `sql_parser.py`
   - Fix: convert to a streaming parser/state machine for large slow query logs.
   - Owner: Backend Developer

## P2 / Nice To Have

1. Docker image uses editable install.
   - File: `Dockerfile`
   - Fix: use `pip install ".[web]"` or build/install a wheel.
   - Owner: DevOps Engineer

2. CI builds Docker but does not run it.
   - File: `.github/workflows/ci.yml`
   - Fix: add Docker smoke test with `/health` check.
   - Owner: DevOps Engineer + QA Engineer

3. Table extraction is narrow.
   - File: `sql_parser.py`
   - Fix: cover quoted schema/table names, CTEs, subqueries, and `INSERT ... SELECT`.
   - Owner: Backend Developer

4. Empty CSV export omits headers.
   - File: `cli.py`
   - Fix: define expected columns per report or document current behavior.
   - Owner: Backend Developer

5. Compose bind mount can hit non-root write permission issues.
   - File: `docker-compose.yml`
   - Fix: consider named volumes or document `data/` ownership setup.
   - Owner: DevOps Engineer

## Suggested Additions

### Backend / CLI

- `parse-errors` report: show source, line number, error reason, and failure rate.
- `search-access` command: filter by status, method, path, IP, and time range.
- `search-sql` command: filter by statement type, table, min duration, and time range.
- `ingest --skip-existing` and `ingest --replace` modes.

### Security

- Optional `WEB_LOG_SQL_TOKEN` auth for dashboard/API.
- Security headers: `X-Content-Type-Options`, `Referrer-Policy`, and a restrictive CSP.
- Broader SQL redaction tests for `INSERT`, `VALUES`, `SET`, JSON payloads, comments, and URL-like strings.
- Docker hardening: `cap_drop: [ALL]`, read-only filesystem where possible, and writable data-only volume.

### QA

- `tests/test_cli.py` for CLI output and DB path behavior.
- `tests/test_web_routes.py` using FastAPI `TestClient`.
- Parser edge tests for `status=-`, `bytes_sent=-`, common logs, invalid timestamp, UTC conversion.
- SQL parser edge tests for `1.5s`, `WITH`, `INSERT INTO`, quoted tables, schema-qualified tables.
- Analyzer filter tests for offset clamp, LIKE filters, method uppercasing, and time range filters.

### DevOps

- `Makefile` with `install`, `test`, `ci`, `docker-build`, `docker-smoke`.
- CI `python -m pip check`.
- CI package build check with `python -m build`.
- Docker smoke test in CI.
- `.env.example` for runtime settings.

## Verified During Review

Commands run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli --help
PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli ingest samples/nginx-access.log --db /tmp/linux-web-log-full-check.db
PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli ingest-sql samples/sql-execution.log --db /tmp/linux-web-log-full-check.db
PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli summary --db /tmp/linux-web-log-full-check.db
PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli sql-summary --db /tmp/linux-web-log-full-check.db
PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli export slow-sql --db /tmp/linux-web-log-full-check.db --format json --limit 3
```

Result:

- Unit tests passed: 12 tests OK.
- Sample access ingest worked: parsed 9, failed 1.
- Sample SQL ingest worked: parsed 4, failed 1.
- Summary, SQL summary, and slow SQL export produced expected output.

## Recommended Next Sprint Order

1. Fix CLI `--db` handling.
2. Fix SQL `INSERT ... VALUES` redaction and add tests.
3. Fix or remove `httpx2`.
4. Add CLI and FastAPI route tests.
5. Add duplicate-ingest policy.
6. Restrict compose host binding and add Docker smoke test.
