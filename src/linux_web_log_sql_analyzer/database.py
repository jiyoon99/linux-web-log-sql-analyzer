from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
import sqlite3

from .parser import ParsedLog, parse_access_log_line
from .sql_parser import ParsedSqlLog, parse_sql_log_file


SCHEMA = """
CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    remote_addr TEXT,
    method TEXT,
    path TEXT,
    query TEXT,
    protocol TEXT,
    status INTEGER,
    bytes_sent INTEGER,
    referrer TEXT,
    user_agent TEXT,
    requested_at TEXT,
    raw_line TEXT NOT NULL,
    parse_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_access_logs_status ON access_logs(status);
CREATE INDEX IF NOT EXISTS idx_access_logs_remote_addr ON access_logs(remote_addr);
CREATE INDEX IF NOT EXISTS idx_access_logs_path ON access_logs(path);
CREATE INDEX IF NOT EXISTS idx_access_logs_requested_at ON access_logs(requested_at);
CREATE INDEX IF NOT EXISTS idx_access_logs_source_line ON access_logs(source, line_no);

CREATE TABLE IF NOT EXISTS sql_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    statement TEXT,
    statement_type TEXT,
    table_name TEXT,
    duration_ms REAL,
    lock_time_ms REAL,
    rows_sent INTEGER,
    rows_examined INTEGER,
    executed_at TEXT,
    raw_entry TEXT NOT NULL,
    parse_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sql_logs_statement_type ON sql_logs(statement_type);
CREATE INDEX IF NOT EXISTS idx_sql_logs_table_name ON sql_logs(table_name);
CREATE INDEX IF NOT EXISTS idx_sql_logs_duration_ms ON sql_logs(duration_ms);
CREATE INDEX IF NOT EXISTS idx_sql_logs_executed_at ON sql_logs(executed_at);
CREATE INDEX IF NOT EXISTS idx_sql_logs_source_line ON sql_logs(source, line_no);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def managed_connect(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


@contextmanager
def _ingest_transaction(conn: sqlite3.Connection) -> Iterator[None]:
    if conn.in_transaction:
        yield
        return

    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()


def insert_log(conn: sqlite3.Connection, log: ParsedLog) -> bool:
    result = conn.execute(
        """
        INSERT INTO access_logs (
            source, line_no, remote_addr, method, path, query, protocol, status,
            bytes_sent, referrer, user_agent, requested_at, raw_line, parse_error
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM access_logs WHERE source = ? AND line_no = ?
        )
        """,
        (
            log.source,
            log.line_no,
            log.remote_addr,
            log.method,
            log.path,
            log.query,
            log.protocol,
            log.status,
            log.bytes_sent,
            log.referrer,
            log.user_agent,
            log.requested_at,
            log.raw_line,
            log.parse_error,
            log.source,
            log.line_no,
        ),
    )
    return result.rowcount > 0


def ingest_file(conn: sqlite3.Connection, log_path: str | Path) -> tuple[int, int, int]:
    init_db(conn)
    path = Path(log_path).resolve()
    source = str(path)
    parsed = 0
    failed = 0
    skipped = 0
    with _ingest_transaction(conn):
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_no, line in enumerate(handle, start=1):
                log = parse_access_log_line(line, source=source, line_no=line_no)
                inserted = insert_log(conn, log)
                if inserted and log.parse_error:
                    failed += 1
                elif inserted:
                    parsed += 1
                else:
                    skipped += 1
    return parsed, failed, skipped


def insert_sql_log(conn: sqlite3.Connection, log: ParsedSqlLog) -> bool:
    result = conn.execute(
        """
        INSERT INTO sql_logs (
            source, line_no, statement, statement_type, table_name, duration_ms,
            lock_time_ms, rows_sent, rows_examined, executed_at, raw_entry, parse_error
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM sql_logs WHERE source = ? AND line_no = ?
        )
        """,
        (
            log.source,
            log.line_no,
            log.statement,
            log.statement_type,
            log.table_name,
            log.duration_ms,
            log.lock_time_ms,
            log.rows_sent,
            log.rows_examined,
            log.executed_at,
            log.raw_entry,
            log.parse_error,
            log.source,
            log.line_no,
        ),
    )
    return result.rowcount > 0


def ingest_sql_file(conn: sqlite3.Connection, log_path: str | Path) -> tuple[int, int, int]:
    init_db(conn)
    path = Path(log_path).resolve()
    parsed = 0
    failed = 0
    skipped = 0
    with _ingest_transaction(conn):
        for log in parse_sql_log_file(path):
            inserted = insert_sql_log(conn, log)
            if inserted and log.parse_error:
                failed += 1
            elif inserted:
                parsed += 1
            else:
                skipped += 1
    return parsed, failed, skipped
