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
    assert [e["type"] for e in target.events(result["run_id"])] == [e["type"] for e in service.events(imported["run"]["id"])]
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
