"""Metadata extraction from Prowler 5.10.0 OCSF JSON arrays.

Field locations verified against the upstream 5.10.0 OCSF output adapter.
This is not a full OCSF validator and does not rewrite native findings.
"""

import json
from .common import Entry


class ProwlerOCSF:
    tool = "prowler"
    version = "1"
    fields = {
        "title": "finding_info.title",
        "provider": "cloud.provider",
        "environment": "cloud.account.uid",
        "asset": "resources.0.uid",
        "region": "cloud.region",
        "severity": "severity",
        # OCSF status is lifecycle state; status_code is Prowler's check result.
        "native_status": "status_code",
        "rule_id": "metadata.event_code",
        "service": "resources.0.group.name",
    }

    def entries(self, content):
        return [Entry(f"$[{i}]", record) for i, record in enumerate(self.records(content))]

    def records(self, content):
        def invalid_constant(value):
            raise ValueError(f"Invalid JSON constant: {value}")

        records = json.loads(content, parse_constant=invalid_constant)
        if not isinstance(records, list):
            raise ValueError("Expected a Prowler OCSF JSON array")
        return records

    def extract(self, record, context=None):
        if not isinstance(record, dict):
            raise ValueError("Finding must be a JSON object")
        product = self.get(record, "metadata.product.name")
        if not isinstance(product, str) or product.lower() != "prowler":
            raise ValueError("Expected metadata.product.name = Prowler")
        if not isinstance(record.get("finding_info"), dict):
            raise ValueError("Missing finding_info object")
        if not isinstance(record["finding_info"].get("title"), str):
            raise ValueError("Missing finding_info.title string")
        result, provenance = {}, {}
        for name, path in self.fields.items():
            value = self.get(record, path)
            if value is not None and not isinstance(value, (str, int, float)):
                raise ValueError(f"Expected scalar metadata at {path}")
            result[name] = None if value is None else str(value)
            if value is not None:
                provenance[name] = path
        return result, provenance

    @staticmethod
    def get(record, path):
        value = record
        for part in path.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
                value = value[int(part)]
            else:
                return None
        return value
