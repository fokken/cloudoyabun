"""Application services used by both CLI and HTTP API."""

import hashlib
import json
import re
from pathlib import Path

from .db import decoded, now, uid
from .events import Journal
from .integrations import PARSERS, detect_parser

MAX_IMPORT_BYTES = 25 * 1024 * 1024
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
EFFECTIVE_SEVERITY = "COALESCE(severity_override,severity)"
TRIAGE_FIELDS = {"severity_override", "category", "tags", "disposition", "priority", "notes", "selected", "report_order"}
SORT_FIELDS = {"title", "tool", "provider", "environment", "asset", "severity", "native_status",
               "category", "priority", "disposition", "service", "report_order"}
GROUP_KEY = "json_array(tool,provider,rule_id,CASE WHEN rule_id IS NULL OR rule_id='' THEN id ELSE NULL END)"


class ConflictError(ValueError):
    pass


class Service:
    def __init__(self, db):
        self.db = db

    def create_assessment(self, name, scope):
        if not name.strip() or not scope.strip():
            raise ValueError("An assessment needs a name and an authorized scope")
        item = dict(id=uid(), name=name.strip(), scope=scope.strip(), created_at=now())
        with self.db.connect() as con:
            con.execute("INSERT INTO assessments VALUES (:id,:name,:scope,:created_at)", item)
        return item

    def assessments(self):
        with self.db.connect() as con:
            return [dict(r) for r in con.execute("SELECT * FROM assessments ORDER BY created_at DESC,id")]

    def assessment(self, assessment_id):
        with self.db.connect() as con:
            return decoded(con.execute("SELECT * FROM assessments WHERE id=?", (assessment_id,)).fetchone())

    def import_artifact(self, assessment_id, name, content, adapter="prowler-ocsf", source_run_id=None):
        self.assessment(assessment_id)
        if len(content) > MAX_IMPORT_BYTES:
            raise ValueError("Import exceeds the 25 MiB limit")
        if adapter == "auto":
            adapter = detect_parser(content)
        if adapter not in PARSERS:
            raise ValueError("Unsupported parser adapter")
        parser = PARSERS[adapter]
        if source_run_id:
            source = self.run(source_run_id)
            if source["assessment_id"] != assessment_id or source["tool"] != parser.tool or source["kind"] != "execution":
                raise ValueError("Source execution does not match this assessment and parser")
        digest = hashlib.sha256(content).hexdigest()
        run_id, artifact_id = uid(), uid()
        with self.db.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            existing = con.execute(
                "SELECT id,run_id FROM artifacts WHERE assessment_id=? AND sha256=? AND adapter=? AND parser_version=?",
                (assessment_id, digest, adapter, parser.version)).fetchone()
            if existing:
                run_id = existing["run_id"]
                artifact_id = existing["id"]
            else:
                con.execute("INSERT INTO runs (id,assessment_id,tool,kind,status,started_at) VALUES (?,?,?,'import','running',?)",
                            (run_id, assessment_id, parser.tool, now()))
                con.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?)",
                            (artifact_id, assessment_id, run_id, Path(name).name, digest, adapter, parser.version, content))
            if source_run_id:
                con.execute("INSERT OR IGNORE INTO artifact_sources VALUES (?,?)", (artifact_id, source_run_id))
        if existing:
            return self.import_result(run_id, reused=True)
        journal = Journal(self.db, run_id)
        journal.emit("artifact_saved", {"artifact_id": artifact_id, "sha256": digest, "bytes": len(content),
                                       "adapter": adapter, "parser_version": parser.version}, step="ingestion")
        try:
            records = parser.entries(content)
        except (ValueError, UnicodeError, RecursionError) as exc:
            journal.emit("parse_failed", {"error": str(exc)}, step="ingestion", level="error")
            self.finish_run(run_id, "failed")
            return self.import_result(run_id)
        accepted, errors = [], []
        for entry in records:
            try:
                metadata, provenance = parser.extract(entry.payload, entry.context)
                accepted.append((entry.locator, entry.payload, metadata, provenance))
            except ValueError as exc:
                errors.append({"locator": entry.locator, "error": str(exc)})
        with self.db.connect() as con:
            for locator, record, metadata, provenance in accepted:
                row = dict(id=uid(), assessment_id=assessment_id, run_id=run_id,
                           artifact_id=artifact_id, locator=locator, tool=parser.tool,
                           payload=json.dumps(record, ensure_ascii=False), provenance=json.dumps(provenance), **metadata)
                columns = ",".join(row)
                values = ",".join(":" + key for key in row)
                con.execute(f"INSERT INTO findings ({columns}) VALUES ({values})", row)
        for error in errors:
            journal.emit("record_rejected", error, step="ingestion", level="warning")
        status = "partial" if errors and accepted else "failed" if errors else "succeeded"
        journal.emit("import_completed", {"accepted": len(accepted), "rejected": len(errors), "status": status}, step="ingestion")
        self.finish_run(run_id, status)
        return self.import_result(run_id)

    def import_result(self, run_id, reused=False):
        with self.db.connect() as con:
            count = con.execute("SELECT COUNT(*) FROM findings WHERE run_id=?", (run_id,)).fetchone()[0]
        return dict(run=self.run(run_id), accepted=count, reused=reused)

    def finish_run(self, run_id, status, exit_code=None):
        with self.db.connect() as con:
            con.execute("UPDATE runs SET status=?, ended_at=?, exit_code=? WHERE id=?", (status, now(), exit_code, run_id))

    def run(self, run_id):
        with self.db.connect() as con:
            return decoded(con.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())

    def runs(self, assessment_id):
        self.assessment(assessment_id)
        with self.db.connect() as con:
            return [decoded(r) for r in con.execute("SELECT * FROM runs WHERE assessment_id=? ORDER BY started_at DESC,id", (assessment_id,))]

    def events(self, run_id, after=0, source="", level="", event_type="", q="", limit=500):
        self.run(run_id)
        where, args = ["run_id=?", "seq> ?"], [run_id, after]
        for column, value in (("source", source), ("level", level), ("type", event_type)):
            if value:
                where.append(f"{column}=?")
                args.append(value)
        if q:
            where.append("details LIKE ?")
            args.append(f"%{q}%")
        with self.db.connect() as con:
            return [decoded(r) for r in con.execute(
                f"SELECT * FROM events WHERE {' AND '.join(where)} ORDER BY seq LIMIT ?", (*args, min(max(limit, 1), 5000)))]

    def findings(self, assessment_id, *, q="", sort="title", direction="asc", offset=0, limit=50,
                 grouped=False, group_key="", **filters):
        self.assessment(assessment_id)
        if sort not in SORT_FIELDS or direction not in ("asc", "desc"):
            raise ValueError("Unsupported sorting option")
        sort = EFFECTIVE_SEVERITY if sort == "severity" else sort
        where, args = ["assessment_id=?"], [assessment_id]
        for field in ("tool", "provider", "environment", "category", "severity", "native_status", "disposition", "service", "run_id"):
            if filters.get(field):
                where.append(f"{EFFECTIVE_SEVERITY if field == 'severity' else field}=?")
                args.append(filters[field])
        from .reassessment import SUPPRESSION
        if filters.get('suppression') in ('hide', 'only'):
            where.append(('NOT ' if filters['suppression']=='hide' else '') + SUPPRESSION)
        if filters.get("selected") is not None:
            where.append("selected=?")
            args.append(int(filters["selected"]))
        if filters.get("tag"):
            where.append("EXISTS (SELECT 1 FROM json_each(findings.tags) WHERE value=?)")
            args.append(filters["tag"])
        if q:
            where.append("(title LIKE ? OR asset LIKE ? OR rule_id LIKE ? OR notes LIKE ?)")
            args.extend([f"%{q}%"] * 4)
        if group_key:
            where.append(f"{GROUP_KEY}=?")
            args.append(group_key)
        clause = " AND ".join(where)
        with self.db.connect() as con:
            if grouped:
                # Group before pagination so a repeated check has one heading,
                # even when its children span multiple pages or imports.
                groups = f"SELECT {GROUP_KEY} group_key, MIN(title) title, tool, provider, rule_id, COUNT(*) count, SUM(severity_override IS NOT NULL) override_count, json_group_array(DISTINCT {EFFECTIVE_SEVERITY}) severities, MIN({sort}) sort_value FROM findings WHERE {clause} GROUP BY {GROUP_KEY}"
                total = con.execute(f"SELECT COUNT(*) FROM ({groups})", args).fetchone()[0]
                rows = con.execute(f"SELECT * FROM ({groups}) ORDER BY sort_value IS NULL, sort_value COLLATE NOCASE {direction},group_key LIMIT ? OFFSET ?",
                                   (*args, min(max(limit, 1), 200), max(offset, 0)))
                items = []
                for row in rows:
                    item = dict(row)
                    item["severities"] = json.loads(item["severities"])
                    item["severity"] = item["severities"][0] if len(item["severities"]) == 1 else "Mixed"
                    items.append(item)
                return dict(items=items, total=total)
            total = con.execute(f"SELECT COUNT(*) FROM findings WHERE {clause}", args).fetchone()[0]
            rows = con.execute(f"SELECT * FROM findings WHERE {clause} ORDER BY {sort} IS NULL, {sort} COLLATE NOCASE {direction},id LIMIT ? OFFSET ?",
                               (*args, min(max(limit, 1), 200), max(offset, 0)))
            items = []
            for row in rows:
                item = dict(row)
                del item["payload"]
                items.append(decoded(item))
        return dict(items=items, total=total)

    def overview(self, assessment_id):
        self.assessment(assessment_id)
        with self.db.connect() as con:
            counts = dict(con.execute("SELECT COUNT(*) total, COALESCE(SUM(disposition='unreviewed'),0) unreviewed, COALESCE(SUM(selected),0) selected FROM findings WHERE assessment_id=?", (assessment_id,)).fetchone())
            facets = {}
            for key in ("provider", "environment", "tool", "severity", "native_status", "category", "service"):
                expression = EFFECTIVE_SEVERITY if key == "severity" else key
                facets[key] = [r[0] for r in con.execute(f"SELECT DISTINCT {expression} FROM findings WHERE assessment_id=? AND {expression} IS NOT NULL AND {expression}!='' ORDER BY {expression}", (assessment_id,))]
            counts["runs"] = con.execute("SELECT COUNT(*) FROM runs WHERE assessment_id=?", (assessment_id,)).fetchone()[0]
        return dict(counts=counts, facets=facets)

    def finding(self, finding_id):
        with self.db.connect() as con:
            item = decoded(con.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone())
            item["audit"] = [decoded(r) for r in con.execute("SELECT * FROM audit WHERE finding_id=? ORDER BY timestamp,id", (finding_id,))]
            item["source_executions"] = [r[0] for r in con.execute("SELECT execution_run_id FROM artifact_sources WHERE artifact_id=? ORDER BY execution_run_id", (item["artifact_id"],))]
            from .reassessment import SUPPRESSION
            item['suppressed'] = bool(con.execute('SELECT ' + SUPPRESSION + ' FROM findings WHERE id=?', (finding_id,)).fetchone()[0])
        return item

    def triage(self, finding_id, changes, revision):
        if set(changes) - TRIAGE_FIELDS:
            raise ValueError("Only analyst fields can be edited")
        with self.db.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            previous = decoded(con.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone())
            if previous["revision"] != revision:
                raise ConflictError("This finding changed. Reload it before saving.")
            merged = {key: previous[key] for key in TRIAGE_FIELDS}
            merged.update(changes)
            if merged['severity_override'] is not None and merged['severity_override'] not in SEVERITIES:
                raise ValueError('Invalid severity override')
            if merged["disposition"] not in ("unreviewed", "confirmed", "noise", "needs-review"):
                raise ValueError("Invalid disposition")
            if type(merged["priority"]) is not int or not 0 <= merged["priority"] <= 4:
                raise ValueError("Priority must be 0 (unset) through 4 (highest)")
            if type(merged["selected"]) is not bool or type(merged["report_order"]) is not int:
                raise ValueError("Invalid report selection or order")
            if not isinstance(merged["tags"], list) or len(merged["tags"]) > 50 or any(not isinstance(t, str) or len(t) > 100 for t in merged["tags"]):
                raise ValueError("Tags must be a list of up to 50 short strings")
            for field, maximum in (("category", 100), ("notes", 20000)):
                if not isinstance(merged[field], str) or len(merged[field]) > maximum:
                    raise ValueError(f"Invalid {field}")
            merged["tags"] = sorted(set(t.strip() for t in merged["tags"] if t.strip()))
            serialized = {**merged, "tags": json.dumps(merged["tags"])}
            con.execute(f"UPDATE findings SET {','.join(key + '=:' + key for key in serialized)},revision=revision+1 WHERE id=:id", {**serialized, "id": finding_id})
            con.execute("INSERT INTO audit VALUES (?,?,?,?,?,?)", (uid(), finding_id, now(), "local-analyst",
                        json.dumps({key: previous[key] for key in TRIAGE_FIELDS}), json.dumps(merged)))
        return self.finding(finding_id)

    def bulk_tags(self, assessment_id, targets, tags, mode="add"):
        self.assessment(assessment_id)
        if not targets or len(targets) > 1000 or len({t["id"] for t in targets}) != len(targets):
            raise ValueError("Select 1–1000 distinct findings")
        if mode not in ("add", "remove"):
            raise ValueError("Tag operation must be add or remove")
        if not isinstance(tags, list) or len(tags) > 50 or any(not isinstance(t, str) or len(t) > 100 for t in tags):
            raise ValueError("Supply up to 50 tags, each at most 100 characters")
        tags = {t.strip() for t in tags if t.strip()}
        if not tags:
            raise ValueError("Supply at least one nonempty tag")
        updated = 0
        with self.db.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            for target in targets:
                row = con.execute("SELECT * FROM findings WHERE id=? AND assessment_id=?", (target["id"], assessment_id)).fetchone()
                previous = decoded(row)
                if previous["revision"] != target["revision"]:
                    raise ConflictError("A selected finding changed. No tags were updated. Clear the selection and reload before retrying.")
                current = set(previous["tags"])
                result = sorted(current | tags if mode == "add" else current - tags)
                if len(result) > 50:
                    raise ValueError("A finding would exceed 50 tags. No tags were updated.")
                if result == previous["tags"]:
                    continue
                before = {key: previous[key] for key in TRIAGE_FIELDS}
                after = {**before, "tags": result}
                con.execute("UPDATE findings SET tags=?,revision=revision+1 WHERE id=?", (json.dumps(result), target["id"]))
                con.execute("INSERT INTO audit VALUES (?,?,?,?,?,?)", (uid(), target["id"], now(), "local-analyst", json.dumps(before), json.dumps(after)))
                updated += 1
        return {"updated": updated, "selected": len(targets)}

    def bulk_triage(self, assessment_id, targets, changes):
        self.assessment(assessment_id)
        if not targets or len(targets) > 1000 or len({t['id'] for t in targets}) != len(targets):
            raise ValueError('Select 1–1000 distinct findings')
        if not changes or set(changes) - {'category', 'disposition', 'selected', 'notes', 'notes_mode', 'severity_override'}:
            raise ValueError('Supply category, disposition or report inclusion')
        if changes.get('severity_override') is not None and changes['severity_override'] not in SEVERITIES:
            raise ValueError('Invalid severity override')
        changes = dict(changes)
        notes_mode = changes.pop('notes_mode', None)
        notes = changes.pop('notes', None)
        if notes_mode is not None:
            if notes_mode not in ('append', 'replace', 'clear'):
                raise ValueError('Invalid notes operation')
            if notes_mode != 'clear' and (not isinstance(notes, str) or not notes.strip() or len(notes) > 20000):
                raise ValueError('Supply notes of 1–20000 characters')
            if notes_mode == 'clear' and notes not in (None, ''):
                raise ValueError('Clear notes does not accept text')
        elif notes is not None or not changes:
            raise ValueError('Choose a notes operation')
        if 'selected' in changes and type(changes['selected']) is not bool:
            raise ValueError('Report inclusion must be true or false')
        if 'category' in changes:
            if not isinstance(changes['category'], str) or len(changes['category']) > 100:
                raise ValueError('Category must be a string of at most 100 characters')
            changes = {**changes, 'category': changes['category'].strip()}
        if 'disposition' in changes and changes['disposition'] not in ('unreviewed', 'confirmed', 'noise', 'needs-review'):
            raise ValueError('Invalid disposition')
        updated = 0
        with self.db.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            for target in targets:
                previous = decoded(con.execute('SELECT * FROM findings WHERE id=? AND assessment_id=?',
                                               (target['id'], assessment_id)).fetchone())
                if previous['revision'] != target['revision']:
                    raise ConflictError('A selected finding changed. No decisions were updated. Clear the selection and reload before retrying.')
                before = {key: previous[key] for key in TRIAGE_FIELDS}
                edits = dict(changes)
                if notes_mode:
                    edits['notes'] = '' if notes_mode == 'clear' else notes if notes_mode == 'replace' else (previous['notes'] + '\n\n' + notes if previous['notes'] else notes)
                    if len(edits['notes']) > 20000:
                        raise ValueError('A finding would exceed 20000 note characters. No decisions were updated.')
                after = {**before, **edits}
                if before == after:
                    continue
                con.execute('UPDATE findings SET '+','.join(key+'=?' for key in edits)+',revision=revision+1 WHERE id=?',
                            [*edits.values(), target['id']])
                con.execute('INSERT INTO audit VALUES (?,?,?,?,?,?)',
                            (uid(), target['id'], now(), 'local-analyst', json.dumps(before), json.dumps(after)))
                updated += 1
        return {'updated': updated, 'selected': len(targets)}

    def artifact(self, artifact_id):
        with self.db.connect() as con:
            row = con.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if row is None:
                raise KeyError("Artifact not found")
            return dict(row)

    def create_report(self, assessment_id):
        assessment = self.assessment(assessment_id)
        with self.db.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            rows = con.execute("SELECT f.*,a.sha256 FROM findings f JOIN artifacts a ON f.artifact_id=a.id WHERE f.assessment_id=? AND f.selected=1 ORDER BY f.category,f.report_order,f.title,f.id", (assessment_id,)).fetchall()
            if not rows:
                raise ValueError("Select at least one finding for the report")
            report_id, timestamp = uid(), now()
            text = [f"# {markdown(assessment['name'])}", "", "Technical assessment report", "",
                    f"Snapshot: {report_id} · {timestamp}", "", "## Authorized scope", "", markdown(assessment["scope"]), ""]
            category = None
            for row in rows:
                f = decoded(row)
                next_category = f["category"] or "Uncategorized"
                if category != next_category:
                    category = next_category
                    text.extend([f"## {markdown(category)}", ""])
                text.extend([f"### {markdown(f['title'] or f['id'])}", "",
                             f"Severity: {markdown(f['effective_severity'] or 'Unspecified')} ({'analyst override' if f['severity_override'] else 'tool'})", "",
                             f"Tool: {markdown(f['tool'])} · Native severity: {markdown(f['severity'] or 'Unspecified')} · Check status: {markdown(f['native_status'] or 'Unspecified')}", "",
                             f"Analyst disposition: {markdown(f['disposition'])} · Priority: {f['priority']}", "",
                             f"Asset: {markdown(f['asset'] or 'Unspecified')}", "",
                             f"Tags: {markdown(', '.join(f['tags']))}", "", markdown(f["notes"]), "",
                             f"Evidence: finding `{f['id']}`, run `{f['run_id']}`, artifact `{f['artifact_id']}`, locator `{f['locator']}`.", "",
                             f"Artifact SHA-256: `{f['sha256']}`", "", "Native tool record:", ""])
                payload = json.dumps(f["payload"], indent=2, ensure_ascii=False)
                fence = "`" * max(3, 1 + max((len(m.group()) for m in re.finditer(r"`+", payload)), default=0))
                text.extend([fence + "json", payload, fence, ""])
            content = "\n".join(text)
            con.execute("INSERT INTO reports VALUES (?,?,?,?,?)", (report_id, assessment_id, timestamp, len(rows), content))
        return self.report(report_id)

    def reports(self, assessment_id):
        self.assessment(assessment_id)
        with self.db.connect() as con:
            return [dict(r) for r in con.execute("SELECT id,assessment_id,created_at,finding_count FROM reports WHERE assessment_id=? ORDER BY created_at DESC,id", (assessment_id,))]

    def report(self, report_id):
        with self.db.connect() as con:
            return decoded(con.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone())


def markdown(value):
    value = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>-])", r"\\\1", value)
