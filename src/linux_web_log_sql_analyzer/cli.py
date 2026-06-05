from __future__ import annotations

import argparse
import csv
import json
import sys

from . import analyzer
from .database import ingest_file, ingest_sql_file, init_db, managed_connect
from .sanitize import safe_csv_value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="web-log-sql")
    parser.add_argument("--db", default="data/logs.db", help="SQLite database path")
    subcommands = parser.add_subparsers(dest="command", required=True)

    init = subcommands.add_parser("init", help="Create database schema")
    _add_db_argument(init)

    ingest = subcommands.add_parser("ingest", help="Parse and ingest an access log file")
    ingest.add_argument("log_file")
    _add_db_argument(ingest)

    ingest_sql = subcommands.add_parser("ingest-sql", help="Parse and ingest a SQL execution or slow query log file")
    ingest_sql.add_argument("log_file")
    _add_db_argument(ingest_sql)

    summary = subcommands.add_parser("summary", help="Print traffic overview and common aggregates")
    _add_db_argument(summary)

    sql_summary = subcommands.add_parser("sql-summary", help="Print SQL log overview and slow query aggregates")
    _add_db_argument(sql_summary)

    export = subcommands.add_parser("export", help="Export one aggregate query")
    export.add_argument("report", choices=sorted(analyzer.EXPORTS))
    export.add_argument("--format", choices=("json", "csv"), default="json")
    export.add_argument("--limit", type=int, default=20)
    _add_db_argument(export)

    serve = subcommands.add_parser("serve", help="Run FastAPI dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=18080)
    _add_db_argument(serve)

    return parser


def _add_db_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        return _serve(args)

    with managed_connect(args.db) as conn:
        init_db(conn)
        if args.command == "init":
            print(f"initialized {args.db}")
            return 0
        if args.command == "ingest":
            parsed, failed, skipped = ingest_file(conn, args.log_file)
            print(f"ingested parsed={parsed} failed={failed} skipped={skipped} db={args.db}")
            return 0
        if args.command == "ingest-sql":
            parsed, failed, skipped = ingest_sql_file(conn, args.log_file)
            print(f"ingested-sql parsed={parsed} failed={failed} skipped={skipped} db={args.db}")
            return 0
        if args.command == "summary":
            _print_summary(conn)
            return 0
        if args.command == "sql-summary":
            _print_sql_summary(conn)
            return 0
        if args.command == "export":
            rows = analyzer.EXPORTS[args.report](conn, args.limit)
            _write_rows(rows, args.format)
            return 0

    return 1


def _print_summary(conn) -> None:
    print(json.dumps(analyzer.overview(conn), ensure_ascii=False, indent=2))
    for name in ("status", "top-paths", "suspicious-ips", "hourly"):
        func = analyzer.EXPORTS[name]
        print(f"\n## {name}")
        print(json.dumps(func(conn, 10), ensure_ascii=False, indent=2))


def _print_sql_summary(conn) -> None:
    print(json.dumps(analyzer.sql_overview(conn), ensure_ascii=False, indent=2))
    for name in ("slow-sql", "sql-types", "sql-tables"):
        print(f"\n## {name}")
        print(json.dumps(analyzer.EXPORTS[name](conn, 10), ensure_ascii=False, indent=2))


def _write_rows(rows: list[dict[str, object]], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return
    if not rows:
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(
        {key: safe_csv_value(value) for key, value in row.items()}
        for row in rows
    )


def _serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print('FastAPI dashboard requires: pip install -e ".[web]"', file=sys.stderr)
        return 2

    from .web import create_app

    app = create_app(args.db)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
