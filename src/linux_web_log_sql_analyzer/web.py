from __future__ import annotations

from html import escape

from . import analyzer
from .database import init_db, managed_connect


def create_app(db_path: str):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse, Response
    except ImportError as exc:
        raise RuntimeError('Install web dependencies with: pip install -e ".[web]"') from exc

    app = FastAPI(title="Linux Web Log SQL Analyzer")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/favicon.ico")
    async def favicon() -> Response:
        return Response(status_code=204)

    @app.get("/api/overview")
    async def api_overview() -> dict[str, object]:
        with managed_connect(db_path) as conn:
            init_db(conn)
            return analyzer.overview(conn)

    @app.get("/api/v1/summary")
    async def api_v1_summary() -> dict[str, object]:
        with managed_connect(db_path) as conn:
            init_db(conn)
            return analyzer.overview(conn)

    @app.get("/api/v1/sql-summary")
    async def api_v1_sql_summary() -> dict[str, object]:
        with managed_connect(db_path) as conn:
            init_db(conn)
            return analyzer.sql_overview(conn)

    @app.get("/api/{report}")
    async def api_report(report: str, limit: int = 20) -> list[dict[str, object]]:
        if report not in analyzer.EXPORTS:
            return []
        with managed_connect(db_path) as conn:
            init_db(conn)
            return analyzer.EXPORTS[report](conn, min(max(limit, 1), 100))

    @app.get("/api/v1/metrics/{report}")
    async def api_v1_report(report: str, limit: int = 20) -> list[dict[str, object]]:
        if report not in analyzer.EXPORTS:
            return []
        with managed_connect(db_path) as conn:
            init_db(conn)
            return analyzer.EXPORTS[report](conn, min(max(limit, 1), 100))

    @app.get("/api/v1/logs")
    async def api_v1_logs(
        status: str | None = None,
        method: str | None = None,
        path: str | None = None,
        remote_addr: str | None = None,
        from_time: str | None = None,
        to_time: str | None = None,
        limit: str | None = "50",
        offset: str | None = "0",
    ) -> list[dict[str, object]]:
        with managed_connect(db_path) as conn:
            init_db(conn)
            return analyzer.search_access_logs(
                conn,
                status=_optional_int(status, name="status"),
                method=_blank_to_none(method),
                path=_blank_to_none(path),
                remote_addr=_blank_to_none(remote_addr),
                from_time=_blank_to_none(from_time),
                to_time=_blank_to_none(to_time),
                limit=_optional_int(limit, 50, name="limit") or 50,
                offset=_optional_int(offset, 0, name="offset") or 0,
            )

    @app.get("/api/v1/sql-logs")
    async def api_v1_sql_logs(
        statement_type: str | None = None,
        table_name: str | None = None,
        min_duration_ms: str | None = None,
        from_time: str | None = None,
        to_time: str | None = None,
        limit: str | None = "50",
        offset: str | None = "0",
    ) -> list[dict[str, object]]:
        with managed_connect(db_path) as conn:
            init_db(conn)
            return analyzer.search_sql_logs(
                conn,
                statement_type=_blank_to_none(statement_type),
                table_name=_blank_to_none(table_name),
                min_duration_ms=_optional_float(min_duration_ms, name="min_duration_ms"),
                from_time=_blank_to_none(from_time),
                to_time=_blank_to_none(to_time),
                limit=_optional_int(limit, 50, name="limit") or 50,
                offset=_optional_int(offset, 0, name="offset") or 0,
            )

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(
        tab: str | None = None,
        status: str | None = None,
        method: str | None = None,
        path: str | None = None,
        remote_addr: str | None = None,
        statement_type: str | None = None,
        table_name: str | None = None,
        min_duration_ms: str | None = None,
        limit: str | None = "20",
        offset: str | None = "0",
    ) -> str:
        with managed_connect(db_path) as conn:
            init_db(conn)
            overview = analyzer.overview(conn)
            parse_errors = analyzer.parse_errors(conn, 20)
            sections = {
                "Status": analyzer.status_summary(conn, 20),
                "Top Paths": analyzer.top_paths(conn, 20),
                "Suspicious IPs": analyzer.suspicious_ips(conn, 20),
                "Hourly Traffic": analyzer.hourly_traffic(conn, 24),
                "Access Search Results": analyzer.search_access_logs(
                    conn,
                    status=_optional_int(status, name="status"),
                    method=_blank_to_none(method),
                    path=_blank_to_none(path),
                    remote_addr=_blank_to_none(remote_addr),
                    limit=_optional_int(limit, 20, name="limit") or 20,
                    offset=_optional_int(offset, 0, name="offset") or 0,
                ),
                "Slow SQL": analyzer.slow_sql(conn, 20),
                "SQL Types": analyzer.sql_types(conn, 20),
                "SQL Tables": analyzer.sql_tables(conn, 20),
                "SQL Search Results": analyzer.search_sql_logs(
                    conn,
                    statement_type=_blank_to_none(statement_type),
                    table_name=_blank_to_none(table_name),
                    min_duration_ms=_optional_float(min_duration_ms, name="min_duration_ms"),
                    limit=_optional_int(limit, 20, name="limit") or 20,
                    offset=_optional_int(offset, 0, name="offset") or 0,
                ),
                "Parse Errors": parse_errors,
            }
            sql_overview = analyzer.sql_overview(conn)
        active_tab = "sql" if tab == "sql" else "access"
        return _render_dashboard(overview, sql_overview, sections, active_tab=active_tab)

    return app


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _optional_int(value: str | None, default: int | None = None, name: str = "value") -> int | None:
    value = _blank_to_none(value)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        _raise_bad_number(name, value)


def _optional_float(value: str | None, default: float | None = None, name: str = "value") -> float | None:
    value = _blank_to_none(value)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        _raise_bad_number(name, value)


def _raise_bad_number(name: str, value: str) -> None:
    try:
        from fastapi import HTTPException
    except ImportError as exc:  # pragma: no cover
        raise ValueError(f"{name} must be numeric: {value}") from exc
    raise HTTPException(status_code=400, detail=f"{name} must be numeric")


def _render_dashboard(
    overview: dict[str, object],
    sql_overview: dict[str, object],
    sections: dict[str, list[dict[str, object]]],
    active_tab: str = "access",
) -> str:
    access_active = " active" if active_tab == "access" else ""
    sql_active = " active" if active_tab == "sql" else ""
    parse_active = " active" if active_tab == "parse" else ""
    access_cards = _render_cards(
        [
            ("Requests", overview.get("total", 0)),
            ("Parse Errors", overview.get("parse_errors", 0)),
            ("4xx", overview.get("client_errors", 0)),
            ("5xx", overview.get("server_errors", 0)),
            ("Unique IPs", overview.get("unique_ips", 0)),
            ("Paths", overview.get("unique_paths", 0)),
        ]
    )
    sql_cards = _render_cards(
        [
            ("SQL Entries", sql_overview.get("total", 0)),
            ("Parse Errors", sql_overview.get("parse_errors", 0)),
            ("Avg ms", sql_overview.get("avg_duration_ms", 0)),
            ("Max ms", sql_overview.get("max_duration_ms", 0)),
            ("Tables", sql_overview.get("unique_tables", 0)),
            ("Types", sql_overview.get("statement_types", 0)),
        ]
    )
    parse_cards = _render_cards([("Parse Errors", len(sections.get("Parse Errors", [])))])
    status_chart = _render_bar_chart("Status Distribution", sections.get("Status", []), "status", "requests")
    hourly_chart = _render_bar_chart("Hourly Requests", sections.get("Hourly Traffic", []), "hour", "requests")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Linux Web Log SQL Analyzer</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f6f7f9; color: #1d2430; }}
    header {{ padding: 22px 32px; background: #263238; color: white; }}
    header h1 {{ margin: 0; font-size: 24px; font-weight: 700; }}
    header p {{ margin: 6px 0 0; color: #cfd8dc; font-size: 14px; }}
    main {{ padding: 24px 32px 40px; max-width: 1240px; margin: 0 auto; }}
    .tabs {{ display: flex; gap: 8px; margin-bottom: 18px; border-bottom: 1px solid #d8dde5; }}
    .tab-button {{ appearance: none; border: 0; border-bottom: 3px solid transparent; background: transparent; padding: 12px 14px 10px; font-size: 14px; font-weight: 700; color: #5b6778; cursor: pointer; }}
    .tab-button.active {{ border-bottom-color: #2f7d6d; color: #1d2430; }}
    .tab-panel {{ display: none; }}
    .tab-panel.active {{ display: block; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }}
    .card {{ background: white; border: 1px solid #d8dde5; border-radius: 8px; padding: 14px; min-height: 82px; }}
    .card span {{ display: block; color: #667085; font-size: 13px; }}
    .card strong {{ display: block; margin-top: 8px; font-size: 24px; line-height: 1.1; }}
    .toolbar {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; margin: 18px 0; padding: 14px; background: white; border: 1px solid #d8dde5; border-radius: 8px; }}
    label {{ display: grid; gap: 5px; color: #667085; font-size: 12px; font-weight: 700; }}
    input, select {{ width: 100%; border: 1px solid #c9d1dc; border-radius: 6px; padding: 9px 10px; color: #1d2430; background: white; font-size: 14px; }}
    .toolbar button {{ align-self: end; border: 0; border-radius: 6px; padding: 10px 12px; background: #2f7d6d; color: white; font-weight: 700; cursor: pointer; }}
    .split {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-top: 16px; }}
    section {{ margin-top: 20px; }}
    .panel {{ background: white; border: 1px solid #d8dde5; border-radius: 8px; padding: 16px; }}
    .panel h2 {{ margin: 0 0 12px; font-size: 17px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d8dde5; border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #e7ebf0; text-align: left; font-size: 13px; vertical-align: top; }}
    th {{ background: #eef1f5; color: #475467; font-size: 12px; }}
    tr:last-child td {{ border-bottom: 0; }}
    .bar-row {{ display: grid; grid-template-columns: minmax(80px, 170px) 1fr 48px; gap: 10px; align-items: center; margin: 9px 0; }}
    .bar-label {{ overflow-wrap: anywhere; font-size: 13px; color: #344054; }}
    .bar-track {{ height: 12px; border-radius: 999px; background: #e7ebf0; overflow: hidden; }}
    .bar-fill {{ height: 100%; background: #2f7d6d; }}
    .bar-value {{ text-align: right; font-size: 13px; color: #667085; }}
    .empty {{ color: #667085; font-size: 14px; }}
    @media (max-width: 640px) {{
      header {{ padding: 18px 18px; }}
      main {{ padding: 18px; }}
      .tabs {{ overflow-x: auto; }}
      .bar-row {{ grid-template-columns: 1fr; gap: 5px; }}
      .bar-value {{ text-align: left; }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Linux Web Log SQL Analyzer</h1>
    <p>Traffic, error, and slow query analysis from local log files.</p>
  </header>
  <main>
    <nav class="tabs" aria-label="Dashboard sections">
      <button class="tab-button{access_active}" type="button" data-tab="access">Access Logs</button>
      <button class="tab-button{sql_active}" type="button" data-tab="sql">SQL Logs</button>
      <button class="tab-button{parse_active}" type="button" data-tab="parse">Parse Errors</button>
    </nav>

    <div id="access" class="tab-panel{access_active}">
      <div class="grid">{access_cards}</div>
      {_render_access_filters()}
      <div class="split">
        {status_chart}
        {hourly_chart}
      </div>
      {_render_table("Access Search Results", sections.get("Access Search Results", []))}
      {_render_table("Top Paths", sections.get("Top Paths", []))}
      {_render_table("Suspicious IPs", sections.get("Suspicious IPs", []))}
    </div>

    <div id="sql" class="tab-panel{sql_active}">
      <div class="grid">{sql_cards}</div>
      {_render_sql_filters()}
      {_render_table("SQL Search Results", sections.get("SQL Search Results", []))}
      {_render_table("Slow SQL", sections.get("Slow SQL", []))}
      <div class="split">
        {_render_table("SQL Types", sections.get("SQL Types", []), panel=True)}
        {_render_table("SQL Tables", sections.get("SQL Tables", []), panel=True)}
      </div>
    </div>

    <div id="parse" class="tab-panel{parse_active}">
      <div class="grid">{parse_cards}</div>
      {_render_table("Parse Errors", sections.get("Parse Errors", []))}
    </div>
  </main>
  <script>
    const buttons = document.querySelectorAll(".tab-button");
    const panels = document.querySelectorAll(".tab-panel");
    buttons.forEach((button) => {{
      button.addEventListener("click", () => {{
        buttons.forEach((item) => item.classList.remove("active"));
        panels.forEach((item) => item.classList.remove("active"));
        button.classList.add("active");
        document.getElementById(button.dataset.tab).classList.add("active");
      }});
    }});
  </script>
</body>
</html>"""


def _render_cards(items: list[tuple[str, object]]) -> str:
    return "".join(
        f"<div class='card'><span>{escape(label)}</span><strong>{escape(str(value))}</strong></div>"
        for label, value in items
    )


def _render_access_filters() -> str:
    return """<form class="toolbar" method="get" action="/">
  <input type="hidden" name="tab" value="access">
  <label>Status<input name="status" inputmode="numeric" placeholder="401"></label>
  <label>Method<select name="method"><option value="">Any</option><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option></select></label>
  <label>Path<input name="path" placeholder="/login"></label>
  <label>IP<input name="remote_addr" placeholder="198.51.100.8"></label>
  <label>Limit<input name="limit" inputmode="numeric" value="20"></label>
  <label>Offset<input name="offset" inputmode="numeric" value="0"></label>
  <button type="submit">Apply</button>
</form>"""


def _render_sql_filters() -> str:
    return """<form class="toolbar" method="get" action="/">
  <input type="hidden" name="tab" value="sql">
  <label>Type<select name="statement_type"><option value="">Any</option><option>SELECT</option><option>INSERT</option><option>UPDATE</option><option>DELETE</option></select></label>
  <label>Table<input name="table_name" placeholder="orders"></label>
  <label>Min duration ms<input name="min_duration_ms" inputmode="decimal" placeholder="100"></label>
  <label>Limit<input name="limit" inputmode="numeric" value="20"></label>
  <label>Offset<input name="offset" inputmode="numeric" value="0"></label>
  <button type="submit">Apply</button>
</form>"""


def _render_bar_chart(title: str, rows: list[dict[str, object]], label_key: str, value_key: str) -> str:
    if not rows:
        return f"<section class='panel'><h2>{escape(title)}</h2><p class='empty'>No rows</p></section>"
    values = [float(row.get(value_key) or 0) for row in rows]
    max_value = max(values) or 1
    bars = []
    for row in rows:
        label = escape(str(row.get(label_key, "")))
        value = float(row.get(value_key) or 0)
        width = max(3, round((value / max_value) * 100))
        bars.append(
            "<div class='bar-row'>"
            f"<div class='bar-label'>{label}</div>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{width}%'></div></div>"
            f"<div class='bar-value'>{escape(str(row.get(value_key, 0)))}</div>"
            "</div>"
        )
    return f"<section class='panel'><h2>{escape(title)}</h2>{''.join(bars)}</section>"


def _render_table(title: str, rows: list[dict[str, object]], panel: bool = False) -> str:
    tag_start = "<section class='panel'>" if panel else "<section>"
    tag_end = "</section>"
    if not rows:
        return f"{tag_start}<h2>{escape(title)}</h2><p class='empty'>No rows</p>{tag_end}"
    headers = list(rows[0])
    head = "".join(f"<th>{escape(header)}</th>" for header in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{escape(str(row.get(header, '')))}</td>" for header in headers) + "</tr>"
        for row in rows
    )
    return f"{tag_start}<h2>{escape(title)}</h2><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{tag_end}"
