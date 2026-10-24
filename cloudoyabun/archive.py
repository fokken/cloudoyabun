"""Portable, per-artifact scan archives. No parser is needed to restore one."""

import hashlib
import io
import json
import math
import zipfile
from pathlib import Path

from .db import now, uid
from .service import MAX_IMPORT_BYTES, SEVERITIES

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
FORMAT = "cloudoyabun.scan-archive"
VERSION = 2
FINDING_COLUMNS = ("locator", "tool", "payload", "provenance", "title", "provider", "environment", "asset", "region",
                   "severity", "native_status", "rule_id", "service", "category", "tags", "disposition", "priority",
                   "notes", "selected", "report_order", "revision", "severity_override")
RUN_COLUMNS = ("tool", "kind", "status", "started_at", "ended_at", "exit_code", "command")
EVENT_COLUMNS = ("seq", "timestamp", "elapsed_ms", "step", "attempt", "source", "level", "type", "details")


def _json(value, expected=None):
    if not isinstance(value, str):
        raise ValueError("Invalid archived JSON field")
    try:
        result = json.loads(value, parse_constant=_invalid_constant)
        _safe_values(result)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Invalid archived JSON field") from exc
    if expected is not None and not isinstance(result, expected):
        raise ValueError("Invalid archived JSON structure")
    return result


def _invalid_constant(value):
    raise ValueError("Non-finite JSON value")


def _safe_values(value):
    """Reject values that cannot safely be stored or serialized by the application."""
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Non-finite archived number")
    elif isinstance(value, dict):
        for key, item in value.items():
            _safe_values(key)
            _safe_values(item)
    elif isinstance(value, list):
        for item in value:
            _safe_values(item)


def _integer(value, minimum=-(2**63)):
    return type(value) is int and minimum <= value < 2**63


def _triage(state, serialized=False):
    if not isinstance(state, dict):
        raise ValueError("Invalid archived analyst state")
    required = {"category", "tags", "disposition", "priority", "notes", "selected", "report_order"}
    if not required <= state.keys():
        raise ValueError("Incomplete archived analyst state")
    if state.get("severity_override") is not None and state["severity_override"] not in SEVERITIES:
        raise ValueError("Invalid archived severity override")
    if state["disposition"] not in ("unreviewed", "confirmed", "noise", "needs-review"):
        raise ValueError("Invalid archived disposition")
    if not _integer(state["priority"], 0) or state["priority"] > 4 or not _integer(state["report_order"]):
        raise ValueError("Invalid archived priority or report order")
    if serialized:
        valid_selected = type(state["selected"]) is int and state["selected"] in (0, 1)
    else:
        valid_selected = type(state["selected"]) is bool
    if not valid_selected:
        raise ValueError("Invalid archived report selection")
    for key, limit in (("category", 100), ("notes", 20000)):
        if not isinstance(state[key], str) or len(state[key]) > limit:
            raise ValueError("Invalid archived analyst text")
    tags = _json(state["tags"], list) if serialized else state["tags"]
    if not isinstance(tags, list) or len(tags) > 50 or any(not isinstance(t, str) or len(t) > 100 for t in tags):
        raise ValueError("Invalid archived tags")


def _run_snapshot(con, run_id):
    run = con.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if run is None:
        raise ValueError("Archive references a missing run")
    return {"source_id": run_id, "run": {key: run[key] for key in RUN_COLUMNS},
            "events": [{key: row[key] for key in EVENT_COLUMNS} for row in
                       con.execute("SELECT * FROM events WHERE run_id=? ORDER BY seq", (run_id,))]}


class ScanArchive:
    def __init__(self, db):
        self.db = db

    def export(self, artifact_id):
        with self.db.connect() as con:
            con.execute("BEGIN")
            artifact = con.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if artifact is None:
                raise KeyError("Artifact not found")
            status = con.execute("SELECT status FROM runs WHERE id=?", (artifact["run_id"],)).fetchone()[0]
            if status == "running":
                raise ValueError("Wait for the import to finish before archiving it")
            assessment = con.execute("SELECT name,scope FROM assessments WHERE id=?", (artifact["assessment_id"],)).fetchone()
            findings = []
            for row in con.execute("SELECT * FROM findings WHERE artifact_id=? ORDER BY locator", (artifact_id,)):
                finding = {"source_id": row["id"], **{key: row[key] for key in FINDING_COLUMNS}}
                finding["audit"] = [{key: event[key] for key in ("timestamp", "actor", "before_state", "after_state")}
                                    for event in con.execute("SELECT * FROM audit WHERE finding_id=? ORDER BY timestamp,id", (row["id"],))]
                findings.append(finding)
            sources = [_run_snapshot(con, row[0]) for row in con.execute(
                "SELECT execution_run_id FROM artifact_sources WHERE artifact_id=? ORDER BY execution_run_id", (artifact_id,))]
            manifest = {"format": FORMAT, "version": VERSION, "created_at": now(),
                        "assessment": {"source_id": artifact["assessment_id"], **dict(assessment)},
                        "artifact": {"source_id": artifact_id, **{key: artifact[key] for key in ("name", "sha256", "adapter", "parser_version")}},
                        "import": _run_snapshot(con, artifact["run_id"]), "sources": sources, "findings": findings}
            if any(source["run"]["status"] == "running" for source in sources):
                raise ValueError("Wait for the source execution to finish before archiving it")
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
        mapping = {key: {} for key in ("assessments", "artifacts", "runs", "findings")}

        def remember(kind, record, new_id):
            if manifest["version"] == VERSION:
                mapping[kind][record["source_id"]] = new_id
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
            remember("assessments", assessment, assessment_id)
            import_run_id = self._insert_run(con, assessment_id, manifest["import"])
            remember("runs", manifest["import"], import_run_id)
            artifact_id = uid()
            remember("artifacts", artifact, artifact_id)
            con.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?)",
                        (artifact_id, assessment_id, import_run_id, artifact["name"], artifact["sha256"],
                         artifact["adapter"], artifact["parser_version"], artifact_content))
            for source in manifest["sources"]:
                source_id = self._insert_run(con, assessment_id, source)
                remember("runs", source, source_id)
                con.execute("INSERT INTO artifact_sources VALUES (?,?)", (artifact_id, source_id))
            for finding in manifest["findings"]:
                finding_id = uid()
                remember("findings", finding, finding_id)
                values = {key: finding[key] for key in FINDING_COLUMNS}
                values.update(id=finding_id, assessment_id=assessment_id, run_id=import_run_id, artifact_id=artifact_id)
                con.execute(f"INSERT INTO findings ({','.join(values)}) VALUES ({','.join(':'+key for key in values)})", values)
                for event in finding["audit"]:
                    con.execute("INSERT INTO audit VALUES (?,?,?,?,?,?)", (uid(), finding_id, event["timestamp"], event["actor"],
                                 event["before_state"], event["after_state"]))
            seq = con.execute("SELECT COALESCE(MAX(seq),0)+1 FROM events WHERE run_id=?", (import_run_id,)).fetchone()[0]
            details = {"archive_version": manifest["version"], "archive_sha256": hashlib.sha256(content).hexdigest(),
                       "id_mapping": mapping, "historical_events": "Original IDs and event content retained",
                       "legacy_ids_unavailable": manifest["version"] == 1}
            con.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (import_run_id, seq, now(), 0, "restore", 1, "orchestrator", "info", "archive_restored", json.dumps(details)))
            return {"assessment_id": assessment_id, "artifact_id": artifact_id, "run_id": import_run_id,
                    "findings": len(manifest["findings"]), "reused": False}

    @staticmethod
    def _insert_run(con, assessment_id, snapshot):
        run_id = uid()
        run = snapshot["run"]
        values = {key: run[key] for key in RUN_COLUMNS}
        values.update(id=run_id, assessment_id=assessment_id, worker_pid=None)
        if values["status"] == "running":
            values.update(status="interrupted", ended_at=now())
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
            return _json(raw_manifest.decode("utf-8"), dict), artifact
        except (zipfile.BadZipFile, UnicodeError, json.JSONDecodeError, OSError, RuntimeError) as exc:
            raise ValueError("Invalid scan archive") from exc

    @staticmethod
    def _validate(manifest, content):
        if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or type(manifest.get("version")) is not int or manifest["version"] not in (1, VERSION):
            raise ValueError("Unsupported scan archive format or version")
        try:
            _safe_values(manifest)
        except (UnicodeError, RecursionError) as exc:
            raise ValueError("Invalid archived text or excessive nesting") from exc
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
            if run["status"] not in ("running", "succeeded", "failed", "partial", "interrupted", "cancelled", "timed-out"):
                raise ValueError("Invalid archived run status")
            if run["command"] is not None:
                command = _json(run["command"], list)
                if any(not isinstance(arg, str) for arg in command):
                    raise ValueError("Invalid archived command")
            if run["exit_code"] is not None and not _integer(run["exit_code"]):
                raise ValueError("Invalid archived exit code")
            seqs = set()
            for event in snapshot["events"]:
                if not isinstance(event, dict) or any(key not in event for key in EVENT_COLUMNS):
                    raise ValueError("Invalid archived event")
                if not _integer(event["seq"], 1) or event["seq"] == 2**63 - 1 or event["seq"] in seqs:
                    raise ValueError("Duplicate archived event sequence")
                if not _integer(event["elapsed_ms"], 0) or not _integer(event["attempt"], 1) or any(
                    not isinstance(event[key], str) for key in ("timestamp", "step", "source", "level", "type", "details")
                ):
                    raise ValueError("Invalid archived event fields")
                details = _json(event["details"], dict)
                if event["type"] == "output" and not isinstance(details.get("text"), str):
                    raise ValueError("Invalid archived output event")
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
            if not isinstance(finding["tool"], str) or not finding["tool"]:
                raise ValueError("Invalid archived finding tool")
            for key in ("title", "provider", "environment", "asset", "region", "severity", "native_status", "rule_id", "service"):
                if finding[key] is not None and not isinstance(finding[key], str):
                    raise ValueError("Invalid archived finding metadata")
            if not _integer(finding["revision"], 0) or finding["revision"] == 2**63 - 1:
                raise ValueError("Invalid archived revision")
            _triage(finding, serialized=True)
            _json(finding["payload"])
            _json(finding["provenance"], dict)
            for event in finding["audit"]:
                if not isinstance(event, dict) or any(not isinstance(event.get(key), str) for key in
                                                      ("timestamp", "actor", "before_state", "after_state")):
                    raise ValueError("Invalid archived decision history")
                for key in ("before_state", "after_state"):
                    _triage(_json(event[key], dict))
        if manifest["version"] == VERSION:
            for records in ([assessment], [artifact], [manifest["import"], *sources], findings):
                identifiers = [record.get("source_id") for record in records]
                if any(not isinstance(key, str) or not key for key in identifiers) or len(set(identifiers)) != len(identifiers):
                    raise ValueError("Missing or duplicate archived source IDs")
