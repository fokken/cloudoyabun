import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from cloudoyabun.api import create_app
from cloudoyabun.archive import ScanArchive
from cloudoyabun.db import Database
from cloudoyabun.service import Service


def test_archive_roundtrip_preserves_evidence_decisions_and_logs(service, assessment, content, tmp_path):
    imported = service.import_artifact(assessment["id"], "scan.json", content)
    original = service.findings(assessment["id"])["items"][0]
    service.triage(original["id"], {"category": "storage", "notes": "Investigated", "selected": True,
                                    "severity_override": "High", "tags": ["reviewed"]}, 0)
    source = service.db
    archive = ScanArchive(source).export(original["artifact_id"])
    target = Service(Database(tmp_path / "restored.sqlite3"))
    result = ScanArchive(target.db).restore(archive)
    assert result["findings"] == imported["accepted"]
    restored = target.findings(result["assessment_id"])["items"]
    item = next(row for row in restored if row["locator"] == original["locator"])
    detail = target.finding(item["id"])
    assert item["id"] != original["id"]
    assert detail["category"] == "storage"
    assert detail["severity"] == original["severity"]
    assert detail["effective_severity"] == "High"
    assert detail["selected"] and detail["notes"] == "Investigated"
    assert detail["tags"] == ["reviewed"]
    assert len(detail["audit"]) == 1
    assert target.artifact(result["artifact_id"])["content"] == content
    events = target.events(result["run_id"])
    assert [e["type"] for e in events[:-1]] == [e["type"] for e in service.events(imported["run"]["id"])]
    assert events[-1]["type"] == "archive_restored"
    mapping = events[-1]["details"]["id_mapping"]
    assert mapping["artifacts"][original["artifact_id"]] == result["artifact_id"]
    assert mapping["findings"][original["id"]] == item["id"]
    assert mapping["runs"][imported["run"]["id"]] == result["run_id"]
    assert mapping["assessments"][assessment["id"]] == result["assessment_id"]
    assert events[0]["details"]["artifact_id"] == original["artifact_id"]
    again = ScanArchive(target.db).restore(archive, result["assessment_id"])
    assert again["reused"] and again["artifact_id"] == result["artifact_id"]
    assert len(target.finding(item["id"])["audit"]) == 1


def test_archive_rejects_checksum_tamper_without_creating_assessment(service, assessment, content, tmp_path):
    imported = service.import_artifact(assessment["id"], "scan.json", content)
    artifact_id = service.findings(assessment["id"])["items"][0]["artifact_id"]
    archive = ScanArchive(service.db).export(artifact_id)
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        metadata = source.read("manifest.json")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as target:
        target.writestr("manifest.json", metadata)
        target.writestr("artifact.bin", b"tampered")
    target = Service(Database(tmp_path / "empty.sqlite3"))
    with pytest.raises(ValueError, match="checksum"):
        ScanArchive(target.db).restore(output.getvalue())
    assert target.assessments() == []
    assert imported["accepted"] > 0


def test_archive_preserves_linked_execution_history(service, assessment, content, tmp_path):
    with service.db.connect() as con:
        con.execute("INSERT INTO runs (id,assessment_id,tool,kind,status,started_at,ended_at,exit_code,command) "
                    "VALUES (?,?,?,'execution','succeeded',?,?,0,?)",
                    ("source-run", assessment["id"], "prowler", "2026-01-01", "2026-01-01", '["prowler"]'))
        con.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)",
                    ("source-run", 1, "2026-01-01", 4, "scan", 1, "stdout", "info", "output", '{"text":"completed"}'))
    service.import_artifact(assessment["id"], "scan.json", content, source_run_id="source-run")
    artifact_id = service.findings(assessment["id"])["items"][0]["artifact_id"]
    target = Service(Database(tmp_path / "linked.sqlite3"))
    restored = ScanArchive(target.db).restore(ScanArchive(service.db).export(artifact_id))
    finding = target.findings(restored["assessment_id"])["items"][0]
    source_ids = target.finding(finding["id"])["source_executions"]
    assert len(source_ids) == 1 and source_ids[0] != "source-run"
    assert target.events(source_ids[0])[0]["details"] == {"text": "completed"}


def test_archive_http_download_and_restore(tmp_path, content):
    with TestClient(create_app(tmp_path / "http.sqlite3")) as client:
        client.headers["X-CloudOyabun-Token"] = client.get("/api/session").json()["token"]
        assessment = client.post("/api/assessments", json={"name": "One", "scope": "Demo"}).json()
        root = f"/api/assessments/{assessment['id']}"
        client.post(root + "/imports?filename=demo.json", content=content)
        listed = client.get(root + "/scan-archives").json()
        assert len(listed) == 1
        downloaded = client.get(f"/api/artifacts/{listed[0]['id']}/archive")
        assert downloaded.status_code == 200
        with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
            assert json.loads(archive.read("manifest.json"))["format"] == "cloudoyabun.scan-archive"
        other = client.post("/api/assessments", json={"name": "Two", "scope": "Demo"}).json()
        restored = client.post(f"/api/assessments/{other['id']}/restore", content=downloaded.content)
        assert restored.status_code == 200
        assert restored.json()["findings"] == 6


def rewrite_archive(content, mutate):
    with zipfile.ZipFile(io.BytesIO(content)) as source:
        manifest = json.loads(source.read("manifest.json"))
        artifact = source.read("artifact.bin")
    mutate(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as target:
        target.writestr("manifest.json", json.dumps(manifest))
        target.writestr("artifact.bin", artifact)
    return output.getvalue()


@pytest.mark.parametrize("path,value", [
    (("import", "run", "command"), "not-json"),
    (("import", "run", "command"), "{}"),
    (("import", "run", "command"), '[1]'),
    (("import", "run", "status"), "bogus"),
    (("import", "events", 0, "seq"), 0),
    (("import", "events", 0, "seq"), 2**63 - 1),
    (("import", "events", 0, "details"), "null"),
    (("import", "events", 0, "elapsed_ms"), -1),
    (("findings", 0, "title"), []),
    (("findings", 0, "title"), "bad\ud800"),
    (("findings", 0, "report_order"), 2**64),
    (("findings", 0, "audit", 0, "after_state"), "null"),
    (("findings", 0, "audit", 0, "before_state"), "[]"),
    (("findings", 0, "audit", 0, "after_state"), '{}'),
    (("findings", 0, "payload"), '{"x": NaN}'),
    (("findings", 0, "source_id"), None),
])
def test_invalid_archive_rejected_before_writes(service, assessment, content, tmp_path, path, value):
    service.import_artifact(assessment["id"], "scan.json", content)
    # Ensure every finding has history, regardless of display/export ordering.
    for finding in service.findings(assessment["id"])["items"]:
        service.triage(finding["id"], {"notes": "Reviewed"}, 0)
    archive = ScanArchive(service.db).export(finding["artifact_id"])
    def mutate(manifest):
        item = manifest
        for key in path[:-1]:
            item = item[key]
        item[path[-1]] = value
    damaged = rewrite_archive(archive, mutate)
    target = Service(Database(tmp_path / "rejected.sqlite3"))
    with pytest.raises(ValueError):
        ScanArchive(target.db).restore(damaged)
    assert target.assessments() == []
    with target.db.connect() as con:
        for table in ("artifacts", "runs", "findings", "events", "audit"):
            assert con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_legacy_archive_restores_with_explicit_provenance_limit(service, assessment, content):
    service.import_artifact(assessment["id"], "scan.json", content)
    finding = service.findings(assessment["id"])["items"][0]
    archive = ScanArchive(service.db).export(finding["artifact_id"])
    def legacy(manifest):
        manifest["version"] = 1
        for item in [manifest["assessment"], manifest["artifact"], manifest["import"], *manifest["sources"], *manifest["findings"]]:
            item.pop("source_id")
    result = ScanArchive(service.db).restore(rewrite_archive(archive, legacy))
    event = service.events(result["run_id"])[-1]
    assert event["type"] == "archive_restored"
    assert event["details"]["legacy_ids_unavailable"] is True
    assert event["details"]["id_mapping"]["findings"] == {}


def test_reexport_keeps_mapping_chain(service, assessment, content):
    service.import_artifact(assessment["id"], "scan.json", content)
    original = service.findings(assessment["id"])["items"][0]
    archives = ScanArchive(service.db)
    first = archives.restore(archives.export(original["artifact_id"]))
    second = archives.restore(archives.export(first["artifact_id"]))
    events = service.events(second["run_id"], event_type="archive_restored")
    assert len(events) == 2
    assert events[0]["details"]["id_mapping"]["artifacts"][original["artifact_id"]] == first["artifact_id"]
    assert events[1]["details"]["id_mapping"]["artifacts"][first["artifact_id"]] == second["artifact_id"]


def test_invalid_archive_http_error_and_retry_token(tmp_path, content):
    app = create_app(tmp_path / "validation.sqlite3")
    service = app.state.service
    assessment = service.create_assessment("Test", "Synthetic")
    service.import_artifact(assessment["id"], "scan.json", content)
    finding = service.findings(assessment["id"])["items"][0]
    archive = ScanArchive(service.db).export(finding["artifact_id"])
    damaged = rewrite_archive(archive, lambda m: m["import"]["run"].update(command="not-json"))
    failed = service.import_artifact(assessment["id"], "bad.json", b"not-json")
    retry_path = f"/api/runs/{failed['run']['id']}/retry-import"
    with TestClient(app) as client:
        assert client.post(retry_path).status_code == 403
        client.headers["X-CloudOyabun-Token"] = client.get("/api/session").json()["token"]
        assert client.post(f"/api/assessments/{assessment['id']}/restore", content=damaged).status_code == 400
        response = client.post(retry_path)
        assert response.status_code == 200
        assert response.json()["run"]["status"] == "failed"
        assert service.findings(assessment["id"])["total"] == 6
