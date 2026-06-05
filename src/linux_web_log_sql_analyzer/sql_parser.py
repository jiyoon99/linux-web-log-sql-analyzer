from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import re

from .sanitize import mask_raw_line, mask_sql_statement, sanitize_text


MYSQL_TIME_RE = re.compile(r"^# Time:\s+(?P<value>.+)$")
MYSQL_QUERY_TIME_RE = re.compile(
    r"^# Query_time:\s+(?P<duration>[0-9.]+)\s+"
    r"Lock_time:\s+(?P<lock>[0-9.]+)\s+"
    r"Rows_sent:\s+(?P<rows_sent>\d+)\s+"
    r"Rows_examined:\s+(?P<rows_examined>\d+)"
)
SIMPLE_EXEC_RE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+"
    r"(?P<duration>[0-9.]+)\s*(?P<unit>ms|s)\s+"
    r"(?P<statement>.+)$",
    re.IGNORECASE,
)
SQL_TYPE_RE = re.compile(r"^\s*(?P<kind>SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|ALTER|DROP)\b", re.IGNORECASE)
TABLE_RE = re.compile(
    r"\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+[`\"]?(?P<table>[A-Za-z_][A-Za-z0-9_.$]*)[`\"]?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ParsedSqlLog:
    source: str
    line_no: int
    statement: Optional[str]
    statement_type: Optional[str]
    table_name: Optional[str]
    duration_ms: Optional[float]
    lock_time_ms: Optional[float]
    rows_sent: Optional[int]
    rows_examined: Optional[int]
    executed_at: Optional[str]
    raw_entry: str
    parse_error: Optional[str]


def parse_sql_log_file(log_path: str | Path) -> list[ParsedSqlLog]:
    path = Path(log_path)
    source = str(path)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    parsed: list[ParsedSqlLog] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        simple = parse_simple_sql_line(line, source=source, line_no=index + 1)
        if simple.parse_error is None:
            parsed.append(simple)
            index += 1
            continue

        mysql_entry, next_index = _parse_mysql_slow_entry(lines, index, source)
        if mysql_entry is not None:
            parsed.append(mysql_entry)
            index = next_index
            continue

        if line.strip():
            parsed.append(_error(source, index + 1, line, "unsupported SQL log format"))
        index += 1
    return parsed


def parse_simple_sql_line(line: str, source: str = "stdin", line_no: int = 0) -> ParsedSqlLog:
    raw_entry = mask_sql_statement(mask_raw_line(line)) or ""
    match = SIMPLE_EXEC_RE.match(raw_entry)
    if not match:
        return _error(source, line_no, raw_entry, "unsupported SQL execution log format")

    duration = float(match.group("duration"))
    if match.group("unit").lower() == "s":
        duration *= 1000
    statement = _normalize_statement(match.group("statement"))
    return ParsedSqlLog(
        source=source,
        line_no=line_no,
        statement=statement,
        statement_type=_statement_type(statement),
        table_name=_table_name(statement),
        duration_ms=duration,
        lock_time_ms=None,
        rows_sent=None,
        rows_examined=None,
        executed_at=_parse_timestamp(match.group("timestamp")),
        raw_entry=raw_entry,
        parse_error=None,
    )


def _parse_mysql_slow_entry(lines: list[str], index: int, source: str) -> tuple[Optional[ParsedSqlLog], int]:
    start_line = index + 1
    executed_at: Optional[str] = None
    duration_ms: Optional[float] = None
    lock_time_ms: Optional[float] = None
    rows_sent: Optional[int] = None
    rows_examined: Optional[int] = None
    statement_lines: list[str] = []
    raw_lines: list[str] = []

    while index < len(lines):
        line = lines[index]
        if raw_lines and MYSQL_TIME_RE.match(line):
            break
        raw_lines.append(line)

        time_match = MYSQL_TIME_RE.match(line)
        query_match = MYSQL_QUERY_TIME_RE.match(line)
        if time_match:
            executed_at = _parse_mysql_time(time_match.group("value"))
        elif query_match:
            duration_ms = float(query_match.group("duration")) * 1000
            lock_time_ms = float(query_match.group("lock")) * 1000
            rows_sent = int(query_match.group("rows_sent"))
            rows_examined = int(query_match.group("rows_examined"))
        elif not line.startswith("#") and not line.upper().startswith("SET TIMESTAMP"):
            statement_lines.append(line)
        index += 1

    if duration_ms is None or not statement_lines:
        return None, start_line

    statement = _normalize_statement(" ".join(statement_lines))
    raw_entry = mask_sql_statement(mask_raw_line("\n".join(raw_lines))) or ""
    return (
        ParsedSqlLog(
            source=source,
            line_no=start_line,
            statement=statement,
            statement_type=_statement_type(statement),
            table_name=_table_name(statement),
            duration_ms=duration_ms,
            lock_time_ms=lock_time_ms,
            rows_sent=rows_sent,
            rows_examined=rows_examined,
            executed_at=executed_at,
            raw_entry=raw_entry,
            parse_error=None,
        ),
        index,
    )


def _normalize_statement(statement: str) -> str:
    normalized = sanitize_text(re.sub(r"\s+", " ", statement.strip().rstrip(";"))) or ""
    return mask_sql_statement(normalized) or ""


def _statement_type(statement: str) -> Optional[str]:
    match = SQL_TYPE_RE.match(statement)
    if not match:
        return None
    kind = match.group("kind").upper()
    return "SELECT" if kind == "WITH" else kind


def _table_name(statement: str) -> Optional[str]:
    match = TABLE_RE.search(statement)
    if not match:
        return None
    return match.group("table")


def _parse_timestamp(value: str) -> Optional[str]:
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def _parse_mysql_time(value: str) -> Optional[str]:
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%y%m%d %H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def _error(source: str, line_no: int, raw_entry: str, message: str) -> ParsedSqlLog:
    return ParsedSqlLog(
        source=source,
        line_no=line_no,
        statement=None,
        statement_type=None,
        table_name=None,
        duration_ms=None,
        lock_time_ms=None,
        rows_sent=None,
        rows_examined=None,
        executed_at=None,
        raw_entry=mask_sql_statement(mask_raw_line(raw_entry)) or "",
        parse_error=message,
    )
