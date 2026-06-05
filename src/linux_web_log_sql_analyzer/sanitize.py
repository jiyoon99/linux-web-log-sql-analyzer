from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import re


SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "auth",
    "jwt",
    "key",
    "password",
    "passwd",
    "refresh_token",
    "secret",
    "session",
    "token",
}
SENSITIVE_PARTS = (
    "apikey",
    "api_key",
    "auth",
    "jwt",
    "password",
    "passwd",
    "secret",
    "session",
    "token",
)

CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def sanitize_text(value: str | None) -> str | None:
    if value is None:
        return None
    value = ANSI_ESCAPE_RE.sub("", value)
    value = CONTROL_CHARS_RE.sub("", value)
    return value.replace("\r", "\\r").replace("\n", "\\n")


def mask_url(value: str | None) -> str | None:
    if value is None:
        return None
    clean = sanitize_text(value)
    if clean is None:
        return None
    split = urlsplit(clean)
    if not split.query:
        return clean
    masked_query = urlencode(
        [
            (key, "***" if is_sensitive_key(key) else query_value)
            for key, query_value in parse_qsl(split.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((split.scheme, split.netloc, split.path, masked_query, split.fragment))


def mask_raw_line(value: str) -> str:
    clean = sanitize_text(value) or ""
    return re.sub(r"([?&;])([^=\s&\"']+)=([^&\s\"']+)", _mask_query_match, clean)


def mask_sql_statement(value: str | None) -> str | None:
    if value is None:
        return None
    clean = sanitize_text(value) or ""
    clean = _mask_insert_values(clean)
    pattern = re.compile(
        r"(?P<prefix>\b[A-Za-z_][A-Za-z0-9_]*\b\s*(?:=|<>|!=|LIKE)\s*)"
        r"(?P<value>'[^']*'|\"[^\"]*\"|[^\s,;)]+)",
        re.IGNORECASE,
    )

    def replace(match: re.Match[str]) -> str:
        column = match.group("prefix").split()[0]
        if not is_sensitive_key(column):
            return match.group(0)
        replacement = "'***'" if match.group("value").startswith(("'", '"')) else "***"
        return match.group("prefix") + replacement

    return pattern.sub(replace, clean)


def is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    if key.lower() in SENSITIVE_KEYS or normalized in SENSITIVE_KEYS:
        return True
    return any(part.replace("_", "") in normalized for part in SENSITIVE_PARTS)


def _mask_query_match(match: re.Match[str]) -> str:
    separator, key, value = match.groups()
    masked = "***" if is_sensitive_key(key) else value
    return f"{separator}{key}={masked}"


INSERT_VALUES_RE = re.compile(
    r"(?P<prefix>\bINSERT\s+INTO\s+[\w`\".]+\s*)"
    r"\((?P<columns>[^)]*)\)"
    r"(?P<middle>\s+VALUES\s*)"
    r"(?P<values>.+)",
    re.IGNORECASE | re.DOTALL,
)


def _mask_insert_values(statement: str) -> str:
    match = INSERT_VALUES_RE.search(statement)
    if not match:
        return statement

    columns = [_clean_sql_identifier(column) for column in _split_sql_list(match.group("columns"))]
    sensitive_indexes = {index for index, column in enumerate(columns) if is_sensitive_key(column)}
    if not sensitive_indexes:
        return statement

    masked_values = _mask_insert_value_groups(match.group("values"), sensitive_indexes)
    return (
        statement[: match.start()]
        + match.group("prefix")
        + "("
        + match.group("columns")
        + ")"
        + match.group("middle")
        + masked_values
    )


def _mask_insert_value_groups(values: str, sensitive_indexes: set[int]) -> str:
    result: list[str] = []
    index = 0
    while index < len(values):
        char = values[index]
        if char != "(":
            result.append(char)
            index += 1
            continue

        end = _find_matching_paren(values, index)
        if end is None:
            result.append(values[index:])
            break

        group = values[index + 1 : end]
        parts = _split_sql_list(group)
        for sensitive_index in sensitive_indexes:
            if sensitive_index < len(parts):
                parts[sensitive_index] = _masked_sql_value(parts[sensitive_index])
        result.append("(" + ",".join(parts) + ")")
        index = end + 1
    return "".join(result)


def _split_sql_list(value: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(value):
        char = value[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    index += 2
                    continue
                quote = None
        elif char in ("'", '"', "`"):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(value[start:index])
            start = index + 1
        index += 1
    parts.append(value[start:])
    return parts


def _find_matching_paren(value: str, start: int) -> int | None:
    depth = 0
    quote: str | None = None
    index = start
    while index < len(value):
        char = value[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    index += 2
                    continue
                quote = None
        elif char in ("'", '"', "`"):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _clean_sql_identifier(value: str) -> str:
    value = value.strip()
    if "." in value:
        value = value.rsplit(".", 1)[-1]
    return value.strip("`\"[] ")


def _masked_sql_value(value: str) -> str:
    leading = value[: len(value) - len(value.lstrip())]
    trailing = value[len(value.rstrip()) :]
    stripped = value.strip()
    if stripped.startswith(("'", '"')):
        quote = stripped[0]
        return f"{leading}{quote}***{quote}{trailing}"
    return f"{leading}***{trailing}"


def safe_csv_value(value: object) -> object:
    if not isinstance(value, str):
        return value
    clean = sanitize_text(value) or ""
    if clean[:1] in ("=", "+", "-", "@"):
        return "'" + clean
    return clean
