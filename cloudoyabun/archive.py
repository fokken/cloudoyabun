"""Portable, per-artifact scan archives. No parser is needed to restore one."""

import hashlib
import io
import json
import zipfile
from pathlib import Path

from .db import now, uid
from .service import MAX_IMPORT_BYTES, SEVERITIES

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
FORMAT = "cloudoyabun.scan-archive"
VERSION = 1
FINDING_COLUMNS = ("locator", "tool", "payload", "provenance", "title", "provider", "environment", "asset", "region",
                   "severity", "native_status", "rule_id", "service", "category", "tags", "disposition", "priority",
                   "notes", "selected", "report_order", "revision", "severity_override")
RUN_COLUMNS = ("tool", "kind", "status", "started_at", "ended_at", "exit_code", "command")
EVENT_COLUMNS = ("seq", "timestamp", "elapsed_ms", "step", "attempt", "source", "level", "type", "details")


def _rows(con, query, args=()):
    return [dict(row) for row in con.execute(query, args)]


def _run_snapshot(con, run_id):
    run = con.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if run is None:
        raise ValueError("Archive references a missing run")
    return {"run": {key: run[key] for key in RUN_COLUMNS},
            "events": [{key: row[key] for key in EVENT_COLUMNS} for row in
                       con.execute("SELECT * FROM events WHERE run_id=? ORDER BY seq", (run_id,))]}


class ScanArchive:
    def __init__(self, db):
        self.db = db

    def export(self, artifact_id):
        with self.db.connect() as con:
            artifact = con.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if artifact is None:
                raise KeyError("Artifact not found")
            status = con.execute("SELECT status FROM runs WHERE id=?", (artifact["run_id"],)).fetchone()[0]
            if status == "running":
                raise ValueError("Wait for the import to finish before archiving it")
            assessment = con.execute("SELECT name,scope FROM assessments WHERE id=?", (artifact["assessment_id"],)).fetchone()
            findings = []
            for row in con.execute("SELECT * FROM findings WHERE artifact_id=? ORDER BY locator", (artifact_id,)):
                finding = {key: row[key] for key in FINDING_COLUMNS}
                finding["audit"] = [{key: event[key] for key in ("timestamp", "actor", "before_state", "after_state")}
                                    for event in con.execute("SELECT * FROM audit WHERE finding_id=? ORDER BY timestamp,id", (row["id"],))]
                findings.append(finding)
            sources = [_run_snapshot(con, row[0]) for row in con.execute(
                "SELECT execution_run_id FROM artifact_sources WHERE artifact_id=? ORDER BY execution_run_id", (artifact_id,))]
            manifest = {"format": FORMAT, "version": VERSION, "created_at": now(),
                        "assessment": dict(assessment),
                        "artifact": {key: artifact[key] for key in ("name", "sha256", "adapter", "parser_version")},
                        "import": _run_snapshot(con, artifact["run_id"]), "sources": sources, "findings": findings}
            content = bytes(artifact["content"])
        metadata = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(metadata) > MAX_MANIFEST_BYTES:
            raise ValueError("Scan metadata exceeds the archive limit")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            archive.writestr("manifest.json", metadata)
            archive.writestr("artifact.bin", content)
        if output.tell() > MAX_ARCHIVE_BYTES:
            raise ValueError("Scan archive exceeds the 64 MiB limit")
        return output.getvalue()

    def restore(self, content, assessment_id=None):
        manifest, artifact_content = self._read(content)
        self._validate(manifest, artifact_content)
        assessment = manifest["assessment"]
        artifact = manifest["artifact"]
        with self.db.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            if assessment_id is None:
                assessment_id = uid()
                con.execute("INSERT INTO assessments VALUES (?,?,?,?)", (assessment_id, assessment["name"], assessment["scope"], now()))
            elif con.execute("SELECT 1 FROM assessments WHERE id=?", (assessment_id,)).fetchone() is None:
                raise KeyError("Assessment not found")
            existing = con.execute("SELECT id,run_id FROM artifacts WHERE assessment_id=? AND sha256=? AND adapter=? AND parser_version=?",
                                   (assessment_id, artifact["sha256"], artifact["adapter"], artifact["parser_version"])).fetchone()
            if existing:
                return {"assessment_id": assessment_id, "artifact_id": existing["id"], "run_id": existing["run_id"],
                        "findings": con.execute("SELECT COUNT(*) FROM findings WHERE artifact_id=?", (existing["id"],)).fetchone()[0],
                        "reused": True}
            import_run_id = self._insert_run(con, assessment_id, manifest["import"])
            artifact_id = uid()
            con.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?)",
                        (artifact_id, assessment_id, import_run_id, artifact["name"], artifact["sha256"],
                         artifact["adapter"], artifact["parser_version"], artifact_content))
            for source in manifest["sources"]:
                source_id = self._insert_run(con, assessment_id, source)
                con.execute("INSERT INTO artifact_sources VALUES (?,?)", (artifact_id, source_id))
            for finding in manifest["findings"]:
                finding_id = uid()
                values = {key: finding[key] for key in FINDING_COLUMNS}
                values.update(id=finding_id, assessment_id=assessment_id, run_id=import_run_id, artifact_id=artifact_id)
                con.execute(f"INSERT INTO findings ({','.join(values)}) VALUES ({','.join(':'+key for key in values)})", values)
                for event in finding["audit"]:
                    con.execute("INSERT INTO audit VALUES (?,?,?,?,?,?)", (uid(), finding_id, event["timestamp"], event["actor"],
                                 event["before_state"], event["after_state"]))
            return {"assessment_id": assessment_id, "artifact_id": artifact_id, "run_id": import_run_id,
                    "findings": len(manifest["findings"]), "reused": False}

    @staticmethod
    def _insert_run(con, assessment_id, snapshot):
        run_id = uid()
        run = snapshot["run"]
        values = {key: run[key] for key in RUN_COLUMNS}
        values.update(id=run_id, assessment_id=assessment_id, worker_pid=None)
        con.execute(f"INSERT INTO runs ({','.join(values)}) VALUES ({','.join(':'+key for key in values)})", values)
        for event in snapshot["events"]:
            values = {key: event[key] for key in EVENT_COLUMNS}
            values["run_id"] = run_id
            con.execute(f"INSERT INTO events ({','.join(values)}) VALUES ({','.join(':'+key for key in values)})", values)
        return run_id

    @staticmethod
    def _read(content):
        if len(content) > MAX_ARCHIVE_BYTES:
            raise ValueError("Scan archive exceeds the 64 MiB limit")
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                members = archive.infolist()
                if sorted(member.filename for member in members) != ["artifact.bin", "manifest.json"]:
                    raise ValueError("Scan archive has unexpected files")
                limits = {"artifact.bin": MAX_IMPORT_BYTES, "manifest.json": MAX_MANIFEST_BYTES}
                if any(member.is_dir() or member.file_size > limits[member.filename] for member in members):
                    raise ValueError("Scan archive member exceeds its limit")
                raw_manifest = archive.read("manifest.json")
                artifact = archive.read("artifact.bin")
            return json.loads(raw_manifest), artifact
        except (zipfile.BadZipFile, UnicodeError, json.JSONDecodeError, OSError, RuntimeError) as exc:
            raise ValueError("Invalid scan archive") from exc

    @staticmethod
    def _validate(manifest, content):
        if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or manifest.get("version") != VERSION:
            raise ValueError("Unsupported scan archive format or version")
        assessment = manifest.get("assessment")
        artifact = manifest.get("artifact")
        if not isinstance(assessment, dict) or not all(isinstance(assessment.get(k), str) and assessment[k].strip()
                                                        for k in ("name", "scope")):
            raise ValueError("Invalid archived assessment")
        if len(assessment["name"]) > 200 or len(assessment["scope"]) > 10000:
            raise ValueError("Archived assessment fields exceed limits")
        if not isinstance(artifact, dict) or not all(isinstance(artifact.get(k), str) for k in
                                                      ("name", "sha256", "adapter", "parser_version")):
            raise ValueError("Invalid archived artifact")
        if not artifact["name"] or Path(artifact["name"]).name != artifact["name"] or len(artifact["name"]) > 255:
            raise ValueError("Invalid archived artifact name")
        if hashlib.sha256(content).hexdigest() != artifact["sha256"]:
            raise ValueError("Archived artifact checksum mismatch")
        if not artifact["adapter"] or not artifact["parser_version"]:
            raise ValueError("Invalid archived parser metadata")
        sources = manifest.get("sources")
        if not isinstance(sources, list):
            raise ValueError("Invalid archived source runs")
        for snapshot, kind in [(manifest.get("import"), "import")] + [(s, "execution") for s in sources]:
            if not isinstance(snapshot, dict) or not isinstance(snapshot.get("run"), dict) or not isinstance(snapshot.get("events"), list):
                raise ValueError("Invalid archived run")
            run = snapshot["run"]
            if any(key not in run for key in RUN_COLUMNS) or run["kind"] != kind:
                raise ValueError("Invalid archived run metadata")
            if any(not isinstance(run[key], str) for key in ("tool", "kind", "status", "started_at")) or not run["tool"]:
                raise ValueError("Invalid archived run metadata")
            if run["ended_at"] is not None and not isinstance(run["ended_at"], str):
                raise ValueError("Invalid archived run metadata")
            if run["exit_code"] is not None and type(run["exit_code"]) is not int:
                raise ValueError("Invalid archived run metadata")
            if run["command"] is not None and not isinstance(run["command"], str):
                raise ValueError("Invalid archived run metadata")
            seqs = set()
            for event in snapshot["events"]:
                if not isinstance(event, dict) or any(key not in event for key in EVENT_COLUMNS):
                    raise ValueError("Invalid archived event")
                if type(event["seq"]) is not int or event["seq"] in seqs:
                    raise ValueError("Duplicate archived event sequence")
                if any(type(event[key]) is not int for key in ("elapsed_ms", "attempt")) or any(
                    not isinstance(event[key], str) for key in ("timestamp", "step", "source", "level", "type", "details")
                ):
                    raise ValueError("Invalid archived event fields")
                try:
                    json.loads(event["details"])
                except ValueError:
                    raise ValueError("Invalid archived event JSON") from None
                seqs.add(event["seq"])
        findings = manifest.get("findings")
        if not isinstance(findings, list):
            raise ValueError("Invalid archived findings")
        locators = set()
        for finding in findings:
            if not isinstance(finding, dict) or any(key not in finding for key in FINDING_COLUMNS) or not isinstance(finding.get("audit"), list):
                raise ValueError("Invalid archived finding")
            locator = finding["locator"]
            if not isinstance(locator, str) or locator in locators:
                raise ValueError("Duplicate or invalid archived finding locator")
            locators.add(locator)
            if finding["severity_override"] is not None and finding["severity_override"] not in SEVERITIES:
                raise ValueError("Invalid archived severity override")
            if not isinstance(finding["tool"], str) or not finding["tool"]:
                raise ValueError("Invalid archived finding tool")
            if finding["disposition"] not in ("unreviewed", "confirmed", "noise", "needs-review"):
                raise ValueError("Invalid archived disposition")
            if any(type(finding[key]) is not int for key in ("priority", "selected", "report_order", "revision")):
                raise ValueError("Invalid archived analyst state")
            if finding["selected"] not in (0, 1) or not 0 <= finding["priority"] <= 4 or finding["revision"] < 0:
                raise ValueError("Invalid archived analyst state")
            if not isinstance(finding["category"], str) or len(finding["category"]) > 100 or not isinstance(finding["notes"], str) or len(finding["notes"]) > 20000:
                raise ValueError("Invalid archived analyst text")
            for key in ("payload", "provenance", "tags"):
                try:
                    value = json.loads(finding[key])
                except (TypeError, ValueError):
                    raise ValueError("Invalid archived finding JSON") from None
                if key == "tags" and (not isinstance(value, list) or len(value) > 50 or any(
                    not isinstance(tag, str) or len(tag) > 100 for tag in value
                )):
                    raise ValueError("Invalid archived tags")
                if key == "provenance" and not isinstance(value, dict):
                    raise ValueError("Invalid archived provenance")
            for event in finding["audit"]:
                if not isinstance(event, dict) or any(not isinstance(event.get(key), str) for key in
                                                      ("timestamp", "actor", "before_state", "after_state")):
                    raise ValueError("Invalid archived decision history")
                for key in ("before_state", "after_state"):
                    try:
                        json.loads(event[key])
                    except ValueError:
                        raise ValueError("Invalid archived decision history") from None
