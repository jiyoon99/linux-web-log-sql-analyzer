# Security and QA Notes

## Security Controls

- Treat access logs as untrusted input.
- Store malformed lines as parse failures instead of raising process-wide errors.
- Mask sensitive URL query values before storage.
- Strip ANSI escape sequences and normalize control characters.
- Use parameterized SQLite queries.
- HTML escape all dashboard values.
- Prefix CSV formula-like string values before export.

## Minimum Test Cases

- Valid nginx combined log line.
- Malformed log line.
- Sensitive query masking.
- Sample file ingest with parse failure retention.
- Status, top path, suspicious IP, and hourly aggregate queries.
- SQL execution log parsing.
- MySQL slow query block parsing.
- Slow SQL, SQL type, and SQL table aggregate queries.

## Known Risks

- The dashboard currently has no authentication. Bind it to `127.0.0.1` for local use.
- Very large files are ingested synchronously.
- Real server log formats may need custom parser support.
- SQL slow query support is best-effort and currently covers common MySQL slow query blocks.
