"""Kubescape resource/control posture JSON (native format v2)."""

import json

from .common import Entry, load_json, metadata


class KubescapeJSON:
    tool = "kubescape"
    version = "1"

    def entries(self, content):
        document = load_json(content)
        if not isinstance(document, dict) or not isinstance(document.get("summaryDetails"), dict):
            raise ValueError("Expected a Kubescape posture report with summaryDetails")
        results = document.get("results", [])
        if not isinstance(results, list):
            raise ValueError("Kubescape results must be an array")
        entries = []
        for i, result in enumerate(results):
            path = f"$.results[{i}]"
            if not isinstance(result, dict) or not isinstance(result.get("controls"), list):
                entries.append(Entry(path, result, {"error": "Expected a resource result with controls array"}))
                continue
            for j, control in enumerate(result["controls"]):
                entries.append(Entry(f"{path}.controls[{j}]", control, {"resource": result, "document": document, "resource_path": path}))
        # Keep summary-only controls (e.g. skipped checks with no resources)
        # visible without duplicating controls already represented by resources.
        represented = {e.payload.get("controlID") for e in entries if isinstance(e.payload, dict) and isinstance(e.payload.get("controlID"), str)}
        summaries = document["summaryDetails"].get("controls", {})
        if not isinstance(summaries, dict):
            raise ValueError("Kubescape summaryDetails.controls must be an object")
        for key, summary in summaries.items():
            if key not in represented:
                entries.append(Entry(f"$.summaryDetails.controls[{json.dumps(key)}]", summary,
                                     {"document": document, "summary": True}))
        return entries

    def extract(self, record, context):
        if "error" in context:
            raise ValueError(context["error"])
        if not isinstance(record, dict) or not isinstance(record.get("controlID"), str) or not record["controlID"]:
            raise ValueError("Kubescape control needs a controlID string")
        doc = context["document"]
        summary = doc["summaryDetails"].get("controls", {}).get(record["controlID"], {})
        if not isinstance(summary, dict):
            summary = {}
        severity = record.get("severity", summary.get("severity"))
        status = record.get("status")
        status_path = "status"
        if isinstance(status, dict):
            status, status_path = status.get("status"), "status.status"
        elif status is None and isinstance(record.get("statusInfo"), dict):
            status, status_path = record["statusInfo"].get("status"), "statusInfo.status"
        resource = context.get("resource", {})
        values = metadata(title=record.get("name") or summary.get("name") or record["controlID"],
                          provider="kubernetes", environment=doc.get("clusterName"),
                          asset=resource.get("resourceID"), severity=severity,
                          native_status=status, rule_id=record["controlID"], service="kubernetes")
        provenance = {"rule_id": "controlID", "native_status": status_path,
                      "provider": "adapter:kubescape platform", "environment": "$.clusterName"}
        provenance["title"] = "name" if record.get("name") else f"$.summaryDetails.controls[{json.dumps(record['controlID'])}].name" if summary.get("name") else "controlID"
        if severity is not None:
            provenance["severity"] = "severity" if "severity" in record else f"$.summaryDetails.controls[{json.dumps(record['controlID'])}].severity"
        if resource:
            provenance["asset"] = context["resource_path"] + ".resourceID"
            provenance["resource_evidence"] = context["resource_path"]
        return values, provenance
