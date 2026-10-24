import json

import pytest

from cloudoyabun.service import ConflictError


def test_invalid_unicode_is_diagnosed_without_stuck_run(service, assessment, record):
    bad = {**record, "finding_info": {**record["finding_info"], "title": "invalid\ud800"}}
    result = service.import_artifact(assessment["id"], "unicode.json", json.dumps([bad, record]).encode())
    assert result["run"]["status"] == "partial"
    assert result["run"]["ended_at"]
    assert result["accepted"] == 1
    errors = service.events(result["run"]["id"], event_type="record_rejected")
    assert errors[0]["details"]["locator"] == "$[0]"


def test_storage_failure_rolls_back_and_can_retry(service, assessment, content):
    with service.db.connect() as con:
        con.execute("CREATE TRIGGER fail_import BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'synthetic storage error'); END")
    result = service.import_artifact(assessment["id"], "scan.json", content)
    assert result["run"]["status"] == "failed" and result["accepted"] == 0
    assert result["run"]["ended_at"]
    assert service.events(result["run"]["id"])[-1]["type"] == "import_failed"
    with service.db.connect() as con:
        con.execute("DROP TRIGGER fail_import")
    retried = service.retry_import(result["run"]["id"])
    assert retried["run"]["status"] == "succeeded" and retried["accepted"] == 6
    assert retried["run"]["id"] == result["run"]["id"]
    assert service.events(result["run"]["id"], event_type="import_retry")
    with pytest.raises(ConflictError):
        service.retry_import(result["run"]["id"])


def test_retry_never_replaces_existing_findings_or_active_runs(service, assessment, content):
    result = service.import_artifact(assessment["id"], "scan.json", content)
    service.finish_run(result["run"]["id"], "failed")
    with pytest.raises(ConflictError, match="contains findings"):
        service.retry_import(result["run"]["id"])
    with service.db.connect() as con:
        con.execute("UPDATE runs SET status='running' WHERE id=?", (result["run"]["id"],))
    with pytest.raises(ConflictError, match="Only failed"):
        service.retry_import(result["run"]["id"])
    assert service.findings(assessment["id"])["total"] == 6


def test_legacy_stuck_import_requires_explicit_recovery(service, assessment, content):
    result = service.import_artifact(assessment["id"], "scan.json", content)
    with service.db.connect() as con:
        con.execute("DELETE FROM findings WHERE run_id=?", (result["run"]["id"],))
        con.execute("UPDATE runs SET status='running',worker_pid=NULL,ended_at=NULL WHERE id=?", (result["run"]["id"],))
    with pytest.raises(ConflictError):
        service.retry_import(result["run"]["id"])
    recovered = service.retry_import(result["run"]["id"], recover_stopped=True)
    assert recovered["run"]["status"] == "succeeded"
    assert recovered["accepted"] == 6
    assert service.events(result["run"]["id"], event_type="import_retry")[-1]["details"]["recovered_stopped_run"]


def test_recovery_refuses_live_worker(service, assessment, content):
    import os
    result = service.import_artifact(assessment["id"], "broken.json", b"not json")
    with service.db.connect() as con:
        con.execute("UPDATE runs SET status='running',worker_pid=? WHERE id=?", (os.getpid(), result["run"]["id"]))
    with pytest.raises(ConflictError, match="still alive"):
        service.retry_import(result["run"]["id"], recover_stopped=True)
