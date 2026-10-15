import hashlib
import json

import pytest

from cloudoyabun.service import ConflictError


def test_native_payload_artifact_and_provenance_survive_import(service, assessment, record):
    record["unfamiliar_vendor_field"] = {"nested": [None, True, "unmodified", 42]}
    content = json.dumps([record], indent=3).encode()
    result = service.import_artifact(assessment["id"], "original.json", content)
    assert result["run"]["status"] == "succeeded"
    f = service.finding(service.findings(assessment["id"])["items"][0]["id"])
    assert f["payload"] == record
    assert f["native_status"] == "FAIL"  # Not OCSF lifecycle status = New.
    assert f["provenance"]["native_status"] == "status_code"
    artifact = service.artifact(f["artifact_id"])
    assert artifact["content"] == content
    assert artifact["sha256"] == hashlib.sha256(content).hexdigest()
    assert f["locator"] == "$[0]"


def test_reimport_retains_triage_and_does_not_duplicate(service, assessment, content):
    first = service.import_artifact(assessment["id"], "a.json", content)
    finding = service.findings(assessment["id"])["items"][0]
    service.triage(finding["id"], {"selected": True, "tags": ["confirmed"], "notes": "Investigated"}, 0)
    second = service.import_artifact(assessment["id"], "renamed.json", content)
    assert second["reused"]
    assert first["run"]["id"] == second["run"]["id"]
    assert service.findings(assessment["id"])["total"] == 6
    current = service.finding(finding["id"])
    assert current["selected"] and current["notes"] == "Investigated"
    assert len(current["audit"]) == 1


def test_assessment_isolation(service, assessment, content):
    other = service.create_assessment("Other", "Other authorized targets")
    for target in (assessment, other):
        service.import_artifact(target["id"], "a.json", content)
    a = service.findings(assessment["id"])["items"][0]
    b = service.findings(other["id"])["items"][0]
    assert a["id"] != b["id"] and a["artifact_id"] != b["artifact_id"]


@pytest.mark.parametrize("content", [b"not json", b'{"not":"array"}', b'[NaN]', b'\xff'])
def test_malformed_import_is_preserved_and_failed(service, assessment, content):
    result = service.import_artifact(assessment["id"], "broken.json", content)
    assert result["run"]["status"] == "failed" and result["accepted"] == 0
    events = service.events(result["run"]["id"])
    artifact_id = events[0]["details"]["artifact_id"]
    assert service.artifact(artifact_id)["content"] == content
    assert events[-1]["type"] == "parse_failed"


def test_partial_import_has_record_diagnostics(service, assessment, record):
    result = service.import_artifact(assessment["id"], "partial.json", json.dumps([record, {"bad": True}, 3]).encode())
    assert result["accepted"] == 1 and result["run"]["status"] == "partial"
    errors = service.events(result["run"]["id"], event_type="record_rejected")
    assert [e["details"]["locator"] for e in errors] == ["$[1]", "$[2]"]


def test_missing_metadata_remains_null(service, assessment, record):
    del record["cloud"]
    del record["severity"]
    service.import_artifact(assessment["id"], "minimal.json", json.dumps([record]).encode())
    finding = service.findings(assessment["id"])["items"][0]
    assert finding["severity"] is None and finding["provider"] is None


def test_triage_conflict_and_immutable_source(service, assessment, content):
    service.import_artifact(assessment["id"], "a.json", content)
    f = service.findings(assessment["id"])["items"][0]
    service.triage(f["id"], {"category": "storage"}, 0)
    with pytest.raises(ConflictError):
        service.triage(f["id"], {"category": "network"}, 0)
    with pytest.raises(ValueError):
        service.triage(f["id"], {"payload": {}}, 1)


def test_filter_sort_and_stable_pagination(service, assessment, content):
    service.import_artifact(assessment["id"], "a.json", content)
    first = service.findings(assessment["id"], sort="title", limit=2)["items"]
    second = service.findings(assessment["id"], sort="title", limit=2, offset=2)["items"]
    assert set(f["id"] for f in first).isdisjoint(f["id"] for f in second)
    matches = service.findings(assessment["id"], provider="aws", severity="High")
    assert matches["total"] == 2
    f = matches["items"][0]
    service.triage(f["id"], {"tags": ["review", "review"], "selected": True}, 0)
    assert service.findings(assessment["id"], tag="review", selected=True)["total"] == 1
    assert service.findings(assessment["id"], q="' OR 1=1 --")["total"] == 0
    with pytest.raises(ValueError):
        service.findings(assessment["id"], sort="title; DROP TABLE findings")


def test_report_freezes_selected_evidence_and_notes(service, assessment, content):
    service.import_artifact(assessment["id"], "a.json", content)
    f = service.findings(assessment["id"])["items"][0]
    service.triage(f["id"], {"selected": True, "notes": "Reviewed evidence", "category": "storage"}, 0)
    report = service.create_report(assessment["id"])
    assert report["finding_count"] == 1
    assert "## storage" in report["content"] and "Reviewed evidence" in report["content"]
    assert f["artifact_id"] in report["content"] and f["locator"] in report["content"]
    assert '"finding_info"' in report["content"]
    service.triage(f["id"], {"notes": "Changed later", "selected": False}, 1)
    assert service.report(report["id"])["content"] == report["content"]
    with pytest.raises(ValueError):
        service.create_report(assessment["id"])


def test_report_orders_findings_and_escapes_untrusted_markup(service, assessment, content):
    service.import_artifact(assessment["id"], "a.json", content)
    a, b = service.findings(assessment["id"])["items"][:2]
    service.triage(a["id"], {"selected": True, "category": "network", "report_order": 2, "notes": "<script>alert(1)</script>"}, 0)
    service.triage(b["id"], {"selected": True, "category": "network", "report_order": 1}, 0)
    text = service.create_report(assessment["id"])["content"]
    assert text.index(b["id"]) < text.index(a["id"])
    assert "<script>" not in text and "&lt;script&gt;" in text
