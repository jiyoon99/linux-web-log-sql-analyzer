from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional
from urllib.parse import urlsplit
import re

from .sanitize import mask_raw_line, mask_url, sanitize_text


ACCESS_LOG_RE = re.compile(
    r'^(?P<remote_addr>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<bytes_sent>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    r'.*$'
)


REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+(?P<protocol>HTTP/\d(?:\.\d)?)$")


@dataclass(frozen=True)
class ParsedLog:
    source: str
    line_no: int
    remote_addr: Optional[str]
    method: Optional[str]
    path: Optional[str]
    query: Optional[str]
    protocol: Optional[str]
    status: Optional[int]
    bytes_sent: Optional[int]
    referrer: Optional[str]
    user_agent: Optional[str]
    requested_at: Optional[str]
    raw_line: str
    parse_error: Optional[str]


def parse_access_log_line(line: str, source: str = "stdin", line_no: int = 0) -> ParsedLog:
    raw_line = mask_raw_line(line.rstrip("\n"))
    match = ACCESS_LOG_RE.match(raw_line)
    if not match:
        return _error(source, line_no, raw_line, "unsupported access log format")

    request = match.group("request")
    request_match = REQUEST_RE.match(request)
    if not request_match:
        return _error(source, line_no, raw_line, f"unsupported request format: {request}")

    target = request_match.group("target")
    masked_target = mask_url(target) or target
    split_target = urlsplit(masked_target)
    status = _int_or_none(match.group("status"))
    bytes_sent = _int_or_none(match.group("bytes_sent"))

    return ParsedLog(
        source=source,
        line_no=line_no,
        remote_addr=sanitize_text(match.group("remote_addr")),
        method=sanitize_text(request_match.group("method")),
        path=split_target.path or "/",
        query=split_target.query or None,
        protocol=sanitize_text(request_match.group("protocol")),
        status=status,
        bytes_sent=bytes_sent,
        referrer=mask_url(_none_if_dash(match.group("referrer"))),
        user_agent=sanitize_text(_none_if_dash(match.group("user_agent"))),
        requested_at=_parse_timestamp(match.group("timestamp")),
        raw_line=raw_line,
        parse_error=None,
    )


def _error(source: str, line_no: int, raw_line: str, message: str) -> ParsedLog:
    return ParsedLog(
        source=source,
        line_no=line_no,
        remote_addr=None,
        method=None,
        path=None,
        query=None,
        protocol=None,
        status=None,
        bytes_sent=None,
        referrer=None,
        user_agent=None,
        requested_at=None,
        raw_line=raw_line,
        parse_error=message,
    )


def _int_or_none(value: Optional[str]) -> Optional[int]:
    if value in (None, "-"):
        return None
    return int(value)


def _none_if_dash(value: Optional[str]) -> Optional[str]:
    if value in (None, "-"):
        return None
    return value


def _parse_timestamp(value: str) -> Optional[str]:
    try:
        dt = parsedate_to_datetime(value.replace(" ", " ", 1))
    except (TypeError, ValueError):
        try:
            dt = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()
