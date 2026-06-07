from __future__ import annotations

from collections.abc import Iterable
import sqlite3


MAX_LIMIT = 100


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, object]]:
    return [dict(row) for row in rows]


def clamp_limit(limit: int, maximum: int = MAX_LIMIT) -> int:
    return min(max(limit, 1), maximum)


def clamp_offset(offset: int) -> int:
    return max(offset, 0)


def overview(conn: sqlite3.Connection) -> dict[str, object]:
    row = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN parse_error IS NOT NULL THEN 1 ELSE 0 END) AS parse_errors,
            SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS client_errors,
            SUM(CASE WHEN status BETWEEN 500 AND 599 THEN 1 ELSE 0 END) AS server_errors,
            COUNT(DISTINCT remote_addr) AS unique_ips,
            COUNT(DISTINCT path) AS unique_paths,
            COALESCE(SUM(bytes_sent), 0) AS total_bytes
        FROM access_logs
        """
    ).fetchone()
    return dict(row)


def status_summary(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, object]]:
    limit = clamp_limit(limit)
    return rows_to_dicts(
        conn.execute(
            """
            SELECT status, COUNT(*) AS requests
            FROM access_logs
            WHERE status IS NOT NULL
            GROUP BY status
            ORDER BY requests DESC, status ASC
            LIMIT ?
            """,
            (limit,),
        )
    )


def top_paths(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, object]]:
    limit = clamp_limit(limit)
    return rows_to_dicts(
        conn.execute(
            """
            SELECT path, COUNT(*) AS requests,
                   SUM(CASE WHEN status BETWEEN 400 AND 599 THEN 1 ELSE 0 END) AS errors
            FROM access_logs
            WHERE path IS NOT NULL
            GROUP BY path
            ORDER BY requests DESC, path ASC
            LIMIT ?
            """,
            (limit,),
        )
    )


def suspicious_ips(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, object]]:
    limit = clamp_limit(limit)
    return rows_to_dicts(
        conn.execute(
            """
            SELECT remote_addr,
                   COUNT(*) AS requests,
                   SUM(CASE WHEN status BETWEEN 400 AND 599 THEN 1 ELSE 0 END) AS errors,
                   SUM(CASE WHEN path LIKE '/admin%' OR path LIKE '/login%' THEN 1 ELSE 0 END) AS sensitive_hits
            FROM access_logs
            WHERE remote_addr IS NOT NULL
            GROUP BY remote_addr
            HAVING requests >= 3 OR errors >= 2 OR sensitive_hits >= 1
            ORDER BY sensitive_hits DESC, errors DESC, requests DESC
            LIMIT ?
            """,
            (limit,),
        )
    )


def hourly_traffic(conn: sqlite3.Connection, limit: int = 24) -> list[dict[str, object]]:
    limit = clamp_limit(limit)
    return rows_to_dicts(
        conn.execute(
            """
            SELECT substr(requested_at, 1, 13) || ':00:00Z' AS hour,
                   COUNT(*) AS requests,
                   SUM(CASE WHEN status BETWEEN 400 AND 599 THEN 1 ELSE 0 END) AS errors
            FROM access_logs
            WHERE requested_at IS NOT NULL
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT ?
            """,
            (limit,),
        )
    )


def search_access_logs(
    conn: sqlite3.Connection,
    *,
    status: int | None = None,
    method: str | None = None,
    path: str | None = None,
    remote_addr: str | None = None,
    from_time: str | None = None,
    to_time: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, object]]:
    where = []
    params: list[object] = []
    if status is not None:
        where.append("status = ?")
        params.append(status)
    if method:
        where.append("method = ?")
        params.append(method.upper())
    if path:
        where.append("path LIKE ?")
        params.append(f"%{path}%")
    if remote_addr:
        where.append("remote_addr = ?")
        params.append(remote_addr)
    if from_time:
        where.append("requested_at >= ?")
        params.append(from_time)
    if to_time:
        where.append("requested_at <= ?")
        params.append(to_time)
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    params.extend([clamp_limit(limit), clamp_offset(offset)])
    return rows_to_dicts(
        conn.execute(
            f"""
            SELECT id, requested_at, remote_addr, method, path, status, bytes_sent,
                   user_agent, parse_error
            FROM access_logs
            {where_sql}
            ORDER BY requested_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            params,
        )
    )


def sql_overview(conn: sqlite3.Connection) -> dict[str, object]:
    row = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN parse_error IS NOT NULL THEN 1 ELSE 0 END) AS parse_errors,
            ROUND(COALESCE(AVG(duration_ms), 0), 2) AS avg_duration_ms,
            ROUND(COALESCE(MAX(duration_ms), 0), 2) AS max_duration_ms,
            COUNT(DISTINCT table_name) AS unique_tables,
            COUNT(DISTINCT statement_type) AS statement_types
        FROM sql_logs
        """
    ).fetchone()
    return dict(row)


def slow_sql(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, object]]:
    limit = clamp_limit(limit)
    return rows_to_dicts(
        conn.execute(
            """
            SELECT statement_type, table_name,
                   ROUND(duration_ms, 2) AS duration_ms,
                   rows_examined,
                   substr(statement, 1, 180) AS statement
            FROM sql_logs
            WHERE duration_ms IS NOT NULL
            ORDER BY duration_ms DESC, line_no ASC
            LIMIT ?
            """,
            (limit,),
        )
    )


def sql_types(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, object]]:
    limit = clamp_limit(limit)
    return rows_to_dicts(
        conn.execute(
            """
            SELECT COALESCE(statement_type, 'UNKNOWN') AS statement_type,
                   COUNT(*) AS queries,
                   ROUND(COALESCE(AVG(duration_ms), 0), 2) AS avg_duration_ms,
                   ROUND(COALESCE(MAX(duration_ms), 0), 2) AS max_duration_ms
            FROM sql_logs
            WHERE parse_error IS NULL
            GROUP BY COALESCE(statement_type, 'UNKNOWN')
            ORDER BY queries DESC, max_duration_ms DESC
            LIMIT ?
            """,
            (limit,),
        )
    )


def sql_tables(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, object]]:
    limit = clamp_limit(limit)
    return rows_to_dicts(
        conn.execute(
            """
            SELECT COALESCE(table_name, 'UNKNOWN') AS table_name,
                   COUNT(*) AS queries,
                   ROUND(COALESCE(AVG(duration_ms), 0), 2) AS avg_duration_ms,
                   ROUND(COALESCE(MAX(duration_ms), 0), 2) AS max_duration_ms
            FROM sql_logs
            WHERE parse_error IS NULL
            GROUP BY COALESCE(table_name, 'UNKNOWN')
            ORDER BY max_duration_ms DESC, queries DESC
            LIMIT ?
            """,
            (limit,),
        )
    )


def parse_errors(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, object]]:
    limit = clamp_limit(limit)
    return rows_to_dicts(
        conn.execute(
            """
            SELECT source,
                   line_no,
                   'access' AS log_type,
                   parse_error,
                   raw_line AS raw_text
            FROM access_logs
            WHERE parse_error IS NOT NULL
            UNION ALL
            SELECT source,
                   line_no,
                   'sql' AS log_type,
                   parse_error,
                   raw_entry AS raw_text
            FROM sql_logs
            WHERE parse_error IS NOT NULL
            ORDER BY source ASC, line_no ASC, log_type ASC
            LIMIT ?
            """,
            (limit,),
        )
    )


def search_sql_logs(
    conn: sqlite3.Connection,
    *,
    statement_type: str | None = None,
    table_name: str | None = None,
    min_duration_ms: float | None = None,
    from_time: str | None = None,
    to_time: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, object]]:
    where = []
    params: list[object] = []
    if statement_type:
        where.append("statement_type = ?")
        params.append(statement_type.upper())
    if table_name:
        where.append("table_name LIKE ?")
        params.append(f"%{table_name}%")
    if min_duration_ms is not None:
        where.append("duration_ms >= ?")
        params.append(min_duration_ms)
    if from_time:
        where.append("executed_at >= ?")
        params.append(from_time)
    if to_time:
        where.append("executed_at <= ?")
        params.append(to_time)
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    params.extend([clamp_limit(limit), clamp_offset(offset)])
    return rows_to_dicts(
        conn.execute(
            f"""
            SELECT id, executed_at, statement_type, table_name,
                   ROUND(duration_ms, 2) AS duration_ms,
                   rows_examined,
                   substr(statement, 1, 240) AS statement,
                   parse_error
            FROM sql_logs
            {where_sql}
            ORDER BY duration_ms DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            params,
        )
    )


EXPORTS = {
    "status": status_summary,
    "top-paths": top_paths,
    "suspicious-ips": suspicious_ips,
    "hourly": hourly_traffic,
    "parse-errors": parse_errors,
    "slow-sql": slow_sql,
    "sql-types": sql_types,
    "sql-tables": sql_tables,
}
