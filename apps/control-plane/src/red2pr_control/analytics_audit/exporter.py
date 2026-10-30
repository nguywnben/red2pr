"""Bounded deterministic export serializers with spreadsheet formula neutralization."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from decimal import Decimal
from typing import Any

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def csv_safe_value(value: Any) -> str:
    """Convert one cell to text and neutralize all formula-starting control characters."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        value = canonical_value(value)
    elif isinstance(value, (Decimal, datetime, date)):
        value = str(value)
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def canonical_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            str(k): canonical_value(v)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (tuple, list)):
        return [canonical_value(item) for item in value]
    return value


def render_json(payload: Any) -> str:
    """Render stable UTF-8 JSON; caller must pass an already authorized/redacted payload."""
    return json.dumps(
        canonical_value(payload), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )


def render_csv(rows: Sequence[Mapping[str, Any]], *, fieldnames: Sequence[str] = ()) -> str:
    """Render homogeneous records with stable header order and RFC-compatible quoting."""
    fields = sorted({str(key) for row in rows for key in row} | set(fieldnames))
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(fields)
    for row in rows:
        writer.writerow([csv_safe_value(row.get(field)) for field in fields])
    return buffer.getvalue()
