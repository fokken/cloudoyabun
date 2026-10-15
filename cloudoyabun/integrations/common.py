"""Native record locations and optional indexing context; never rewrite payloads."""

import json
from dataclasses import dataclass, field


def load_json(content):
    def invalid(value):
        raise ValueError(f"Invalid JSON constant: {value}")
    return json.loads(content, parse_constant=invalid)


@dataclass
class Entry:
    locator: str
    payload: object
    context: dict = field(default_factory=dict)


def scalar(value, field_name):
    if value is not None and not isinstance(value, (str, int, float)):
        raise ValueError(f"Expected a scalar at {field_name}")
    return None if value is None else str(value)


def metadata(**values):
    fields = ("title", "provider", "environment", "asset", "region", "severity", "native_status", "rule_id", "service")
    return {key: scalar(values.get(key), key) for key in fields}
