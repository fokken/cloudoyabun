"""SQLite storage. Native evidence and analyst edits live in separate columns."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def uid():
    return uuid4().hex


SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, scope TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
 id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id),
 tool TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT NOT NULL,
 ended_at TEXT, exit_code INTEGER, command TEXT, worker_pid INTEGER
);
CREATE TABLE IF NOT EXISTS events (
 run_id TEXT NOT NULL REFERENCES runs(id), seq INTEGER NOT NULL, timestamp TEXT NOT NULL,
 elapsed_ms INTEGER NOT NULL, step TEXT NOT NULL, attempt INTEGER NOT NULL,
 source TEXT NOT NULL, level TEXT NOT NULL, type TEXT NOT NULL, details TEXT NOT NULL,
 PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS artifacts (
 id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id),
 run_id TEXT NOT NULL REFERENCES runs(id), name TEXT NOT NULL, sha256 TEXT NOT NULL,
 adapter TEXT NOT NULL, parser_version TEXT NOT NULL, content BLOB NOT NULL,
 UNIQUE (assessment_id, sha256, adapter, parser_version)
);
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id),
 run_id TEXT NOT NULL REFERENCES runs(id), artifact_id TEXT NOT NULL REFERENCES artifacts(id),
 locator TEXT NOT NULL, tool TEXT NOT NULL, payload TEXT NOT NULL, provenance TEXT NOT NULL,
 title TEXT, provider TEXT, environment TEXT, asset TEXT, region TEXT,
 severity TEXT, native_status TEXT, rule_id TEXT, service TEXT,
 category TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '[]',
 disposition TEXT NOT NULL DEFAULT 'unreviewed', priority INTEGER NOT NULL DEFAULT 0,
 notes TEXT NOT NULL DEFAULT '', selected INTEGER NOT NULL DEFAULT 0,
 report_order INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0,
 UNIQUE (artifact_id, locator)
);
CREATE INDEX IF NOT EXISTS findings_assessment ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS runs_assessment ON runs(assessment_id);
CREATE TABLE IF NOT EXISTS audit (
 id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id),
 timestamp TEXT NOT NULL, actor TEXT NOT NULL, before_state TEXT NOT NULL, after_state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
 id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id),
 created_at TEXT NOT NULL, finding_count INTEGER NOT NULL, content TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_analyses (
 id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id),
 created_at TEXT NOT NULL, model TEXT NOT NULL, prompt_version TEXT NOT NULL,
 endpoint TEXT NOT NULL, protocol TEXT NOT NULL,
 evidence TEXT NOT NULL, status TEXT NOT NULL, result TEXT NOT NULL DEFAULT '{}',
 usage TEXT NOT NULL DEFAULT '{}', error TEXT, run_id TEXT REFERENCES runs(id),
 review_status TEXT NOT NULL DEFAULT 'unreviewed', reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS ai_assessment ON ai_analyses(assessment_id);
CREATE TABLE IF NOT EXISTS suppression_rules (
 id TEXT PRIMARY KEY, created_at TEXT NOT NULL, tool TEXT NOT NULL, provider TEXT NOT NULL,
 environment TEXT NOT NULL, rule_id TEXT NOT NULL, asset TEXT NOT NULL, native_status TEXT NOT NULL,
 reason TEXT NOT NULL, expires_at TEXT, enabled INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS comparisons (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, snapshot TEXT NOT NULL, applied INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS workflow_audit (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifact_sources (
 artifact_id TEXT NOT NULL REFERENCES artifacts(id), execution_run_id TEXT NOT NULL REFERENCES runs(id),
 PRIMARY KEY (artifact_id, execution_run_id)
);
"""


class Database:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as con:
            version = con.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, 3, 4, 5):
                raise ValueError(f"Unsupported database schema version: {version}")
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(SCHEMA)
            columns = {r[1] for r in con.execute('PRAGMA table_info(ai_analyses)')}
            for name, default in (('plan', '{}'), ('batches', '[]')):
                if name not in columns:
                    con.execute(f"ALTER TABLE ai_analyses ADD COLUMN {name} TEXT NOT NULL DEFAULT '{default}'")
            finding_columns = {r[1] for r in con.execute('PRAGMA table_info(findings)')}
            if 'severity_override' not in finding_columns:
                con.execute('ALTER TABLE findings ADD COLUMN severity_override TEXT')
            if version < 5:
                con.execute("PRAGMA user_version=5")
        self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        try:
            with con:
                yield con
        finally:
            con.close()


def decoded(row):
    if row is None:
        raise KeyError("Record not found")
    result = dict(row)
    for key in ("payload", "provenance", "tags", "details", "command", "before_state", "after_state"):
        if key in result and result[key] is not None:
            result[key] = json.loads(result[key])
    if "selected" in result:
        result["selected"] = bool(result["selected"])
    if 'severity_override' in result and 'severity' in result:
        result['effective_severity'] = result['severity_override'] or result['severity']
    return result
