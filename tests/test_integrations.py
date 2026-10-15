import copy
import json
import os
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient

from cloudoyabun.api import create_app
from cloudoyabun.cli import main
from cloudoyabun.db import Database
from cloudoyabun.integrations import detect_parser
from cloudoyabun.scans import plan_scan, run_scan


@pytest.fixture
def kubescape_content():
    return (Path(__file__).parents[1] / "cloudoyabun/fixtures/kubescape.json").read_bytes()


def test_kubescape_preserves_native_control_and_locator(service, assessment, kubescape_content):
    doc = json.loads(kubescape_content)
    imported = service.import_artifact(assessment["id"], "results.json", kubescape_content, "auto")
    assert imported["accepted"] == 4 and imported["run"]["status"] == "succeeded"
    rows = service.findings(assessment["id"])["items"]
    f = next(f for f in rows if f["locator"] == "$.results[0].controls[0]")
    detail = service.finding(f["id"])
    assert detail["payload"] == doc["results"][0]["controls"][0]
    assert f["asset"] == doc["results"][0]["resourceID"]
    assert f["provider"] == "kubernetes" and f["environment"] == "synthetic-cluster"
    assert f["native_status"] == "failed" and f["severity"] == "High"
    assert service.artifact(f["artifact_id"])["content"] == kubescape_content
    assert f["provenance"]["asset"] == "$.results[0].resourceID"
    summary = next(f for f in rows if f["rule_id"] == "C-0003")
    assert summary["native_status"] == "skipped" and summary["severity"] is None
    assert summary["asset"] is None and summary["locator"].startswith("$.summaryDetails")
    groups = service.findings(assessment["id"], grouped=True)["items"]
    assert next(g for g in groups if g["rule_id"] == "C-0001")["count"] == 2


def test_kubescape_partial_import_logs_bad_control(service, assessment, kubescape_content):
    doc = json.loads(kubescape_content)
    doc["results"][0]["controls"].append({"controlID": []})
    imported = service.import_artifact(assessment["id"], "partial.json", json.dumps(doc).encode(), "kubescape-json")
    assert imported["run"]["status"] == "partial"
    assert service.events(imported["run"]["id"], event_type="record_rejected")[0]["details"]["locator"] == "$.results[0].controls[1]"


def test_format_detection_and_azurehound_not_imported(service, assessment, content, kubescape_content):
    assert detect_parser(content) == "prowler-ocsf"
    assert detect_parser(kubescape_content) == "kubescape-json"
    with pytest.raises(ValueError, match="BloodHound"):
        service.import_artifact(assessment["id"], "azurehound.json", b'{"meta":{"type":"azure"},"data":[]}', "auto")
    assert service.findings(assessment["id"])["total"] == 0


@pytest.mark.parametrize("tool,options,expected", [
    ("prowler", {"provider": "aws"}, ["prowler", "aws"]),
    ("prowler", {"provider": "azure"}, ["prowler", "azure"]),
    ("prowler", {"provider": "gcp"}, ["prowler", "gcp"]),
    ("prowler", {"provider": "m365", "auth": "env"}, ["prowler", "m365"]),
    ("prowler", {"provider": "kubernetes", "context": "lab"}, ["prowler", "kubernetes"]),
    ("kubescape", {"context": "lab"}, ["kubescape", "scan", "framework", "all"]),
    ("azurehound", {"tenant": "example.onmicrosoft.com"}, ["azurehound", "list"]),
])
def test_presets_run_broad_scans(tmp_path, tool, options, expected):
    plan = plan_scan(tool, tmp_path, **options)
    assert plan.command[:len(expected)] == expected
    assert not any(arg in plan.command for arg in ("--checks", "--services", "--include-namespaces", "--exclude-namespaces", "--status"))
    if tool == "prowler":
        assert plan.success_codes == (0, 3) and "json-ocsf" in plan.command
        if options["provider"] in ("azure", "m365"):
            assert ("--sp-env-auth" if options.get("auth") == "env" else "--az-cli-auth") in plan.command
    if tool == "kubescape":
        assert "--keep-local" in plan.command
    if tool == "azurehound":
        assert plan.adapter is None and "--secret" not in plan.command


@pytest.mark.parametrize("tool,options", [("prowler", {}), ("kubescape", {}), ("azurehound", {}),
                                         ("azurehound", {"tenant": "--secret=bad"}),
                                         ("kubescape", {"context": "lab", "provider": "aws"})])
def test_preset_requires_unambiguous_target(tmp_path, tool, options):
    with pytest.raises(ValueError):
        plan_scan(tool, tmp_path, **options)


def fake_tool(tmp_path, monkeypatch, name, content, *, exit_code=0, write=True, sleep=0):
    """Local test double: never authenticates or makes network requests."""
    binary = tmp_path / name
    binary.write_text(f'''#!{sys.executable}
import sys,time
from pathlib import Path
args=sys.argv[1:]
if args == ['--version'] or args == ['version']:
    print('{name} synthetic-test-version'); raise SystemExit(0)
if {write!r}:
    if '{name}' == 'prowler':
        output=Path(args[args.index('--output-directory')+1]) / 'prowler.ocsf.json'
    else:
        output=Path(args[args.index('--output')+1])
    output.write_bytes({content!r})
print('synthetic tool output',flush=True)
time.sleep({sleep!r})
raise SystemExit({exit_code!r})
''')
    binary.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])


def test_prowler_exit_3_imports_and_links_execution(service, assessment, content, tmp_path, monkeypatch):
    fake_tool(tmp_path, monkeypatch, "prowler", content, exit_code=3)
    result = run_scan(service.db, assessment["id"], "prowler", provider="aws")
    assert result["run"]["status"] == "succeeded" and result["run"]["exit_code"] == 3
    assert result["imports"][0]["accepted"] == 6
    f = service.finding(service.findings(assessment["id"])["items"][0]["id"])
    assert f["source_executions"] == [result["run"]["id"]]
    again = run_scan(service.db, assessment["id"], "prowler", provider="aws")
    assert again["imports"][0]["reused"]
    assert len(service.finding(f["id"])["source_executions"]) == 2
    assert service.findings(assessment["id"])["total"] == 6


def test_kubescape_easy_scan_imports(service, assessment, kubescape_content, tmp_path, monkeypatch):
    fake_tool(tmp_path, monkeypatch, "kubescape", kubescape_content)
    result = run_scan(service.db, assessment["id"], "kubescape", context="lab")
    assert result["run"]["status"] == "succeeded" and result["imports"][0]["accepted"] == 4


def test_azurehound_only_collects_without_parsing(service, assessment, tmp_path, monkeypatch):
    raw = b'opaque original bytes: BloodHound owns parsing'
    fake_tool(tmp_path, monkeypatch, "azurehound", raw)
    result = run_scan(service.db, assessment["id"], "azurehound", tenant="example.onmicrosoft.com")
    assert result["run"]["status"] == "succeeded" and result["imports"] == []
    assert Path(result["collections"][0]["path"]).read_bytes() == raw
    assert result["collections"][0]["destination"] == "BloodHound"
    assert service.findings(assessment["id"])["total"] == 0
    with service.db.connect() as con:
        assert con.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 0


@pytest.mark.parametrize("write,raw", [(False, b""), (True, b"malformed JSON")])
def test_missing_or_malformed_output_fails_scan(service, assessment, tmp_path, monkeypatch, write, raw):
    fake_tool(tmp_path, monkeypatch, "prowler", raw, write=write)
    result = run_scan(service.db, assessment["id"], "prowler", provider="aws")
    assert result["run"]["status"] == "failed"
    if write:
        assert result["imports"][0]["run"]["status"] == "failed"
        assert (Path(result["output_directory"]) / 'prowler.ocsf.json').read_bytes() == raw


def test_failed_scan_still_retains_and_imports_partial_evidence(service, assessment, content, tmp_path, monkeypatch):
    fake_tool(tmp_path, monkeypatch, "prowler", content, exit_code=1)
    result = run_scan(service.db, assessment["id"], "prowler", provider="aws")
    assert result["run"]["status"] == "failed" and result["imports"][0]["accepted"] == 6


def test_scan_timeout_keeps_collection_failed(service, assessment, tmp_path, monkeypatch):
    fake_tool(tmp_path, monkeypatch, "azurehound", b'{"partial":true}', sleep=10)
    result = run_scan(service.db, assessment["id"], "azurehound", tenant="lab", timeout=.2)
    assert result["run"]["status"] == "timed-out"
    assert result["collections"][0]["process_status"] == "timed-out"


def test_dry_run_and_cli_import_need_no_installed_tool(service, assessment, kubescape_content, tmp_path, capsys):
    result = run_scan(service.db, assessment["id"], "prowler", provider="aws", dry_run=True)
    assert result["dry_run"] and service.runs(assessment["id"]) == []
    source = tmp_path / "scan.json"
    source.write_bytes(kubescape_content)
    assert main(["--db", str(service.db.path), "import", assessment["id"], str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["accepted"] == 4


def test_web_import_detects_kubescape(tmp_path, kubescape_content):
    with TestClient(create_app(tmp_path / "web.sqlite3")) as client:
        client.headers["X-CloudOyabun-Token"] = client.get("/api/session").json()["token"]
        assessment = client.post("/api/assessments", json={"name": "K8s", "scope": "Synthetic lab"}).json()
        response = client.post(f"/api/assessments/{assessment['id']}/imports", content=kubescape_content)
        assert response.status_code == 200 and response.json()["accepted"] == 4


def test_existing_database_migrates_without_losing_findings(service, assessment, content):
    service.import_artifact(assessment["id"], "scan.json", content)
    with service.db.connect() as con:
        con.execute("DROP TABLE artifact_sources")
        con.execute("PRAGMA user_version=1")
    Database(service.db.path)
    assert service.findings(assessment["id"])["total"] == 6
    with service.db.connect() as con:
        assert con.execute("PRAGMA user_version").fetchone()[0] == 5
