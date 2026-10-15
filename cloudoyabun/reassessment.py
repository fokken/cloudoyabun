"""Explicit repeat-assessment matching and reversible scoped suppression."""
import json
from collections import defaultdict
from datetime import datetime, timezone
from .db import decoded, now, uid
from .service import Service, ConflictError, TRIAGE_FIELDS

IDENTITY = ('tool', 'provider', 'environment', 'asset', 'rule_id')
SUPPRESSION = """EXISTS (SELECT 1 FROM suppression_rules s WHERE s.enabled=1
AND (s.expires_at IS NULL OR s.expires_at > strftime('%Y-%m-%dT%H:%M:%f+00:00','now'))
AND s.tool=findings.tool AND s.provider=findings.provider AND s.environment=findings.environment
AND s.rule_id=findings.rule_id AND (s.asset='' OR s.asset=findings.asset)
AND s.native_status=COALESCE(findings.native_status,''))"""


class Reassessment:
    def __init__(self, db):
        self.db, self.service = db, Service(db)

    def rules(self):
        with self.db.connect() as con:
            return [dict(r) for r in con.execute('SELECT * FROM suppression_rules ORDER BY created_at DESC')]

    def suppress(self, finding_id, reason, expires_at=None, whole_check=False):
        f = self.service.finding(finding_id)
        if not reason.strip() or len(reason) > 2000:
            raise ValueError('Provide a reason of 1–2000 characters')
        if not all(f[k] for k in IDENTITY):
            raise ValueError('Suppression requires tool, provider, environment, asset and check identity')
        if expires_at:
            expiry = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                raise ValueError('Expiry must be a future timestamp with timezone')
            expires_at = expiry.astimezone(timezone.utc).isoformat(timespec='milliseconds')
        rule = dict(id=uid(), created_at=now(), tool=f['tool'], provider=f['provider'], environment=f['environment'],
                    rule_id=f['rule_id'], asset='' if whole_check else f['asset'], native_status=f['native_status'] or '',
                    reason=reason.strip(), expires_at=expires_at, enabled=1)
        with self.db.connect() as con:
            con.execute('INSERT INTO suppression_rules ('+','.join(rule)+') VALUES ('+','.join('?' for _ in rule)+')', list(rule.values()))
            con.execute('INSERT INTO workflow_audit VALUES (?,?,?,?)', (uid(), now(), 'suppression_created', json.dumps(rule)))
        return rule

    def toggle(self, rule_id, enabled):
        with self.db.connect() as con:
            if not con.execute('UPDATE suppression_rules SET enabled=? WHERE id=?', (int(enabled), rule_id)).rowcount:
                raise KeyError('Rule not found')
            con.execute('INSERT INTO workflow_audit VALUES (?,?,?,?)', (uid(), now(), 'suppression_enabled' if enabled else 'suppression_disabled', json.dumps({'id':rule_id})))
        return {'id':rule_id, 'enabled':enabled}

    def artifacts(self):
        with self.db.connect() as con:
            return [dict(r) for r in con.execute('SELECT a.id,a.name,a.assessment_id,s.name assessment_name,r.status FROM artifacts a JOIN assessments s ON s.id=a.assessment_id JOIN runs r ON r.id=a.run_id ORDER BY r.started_at DESC')]

    def compare(self, before_id, after_id):
        if before_id == after_id: raise ValueError('Choose two different imports')
        with self.db.connect() as con:
            headers = [con.execute('SELECT adapter FROM artifacts WHERE id=?', (artifact_id,)).fetchone()
                       for artifact_id in (before_id, after_id)]
        if any(row is None for row in headers):
            raise KeyError('Artifact not found')
        before, after = headers
        if before['adapter'] != after['adapter']: raise ValueError('Compare imports from the same tool format')
        buckets = []
        with self.db.connect() as con:
            for artifact in (before_id, after_id):
                group = defaultdict(list)
                for row in con.execute('SELECT id,revision,title,native_status,severity,category,tags,disposition,priority,notes,severity_override,' + ','.join(IDENTITY) + ' FROM findings WHERE artifact_id=?', (artifact,)):
                    f = decoded(row)
                    key = tuple(f[k] for k in IDENTITY)
                    group[key].append(f)
                buckets.append(group)
        old, new = buckets
        rows = []
        for key in sorted(old.keys() | new.keys(), key=str):
            left, right = old.get(key, []), new.get(key, [])
            status = 'ambiguous' if not all(key) or len(left)>1 or len(right)>1 else 'new' if not left else 'not-observed' if not right else 'unchanged' if all(left[0][k] == right[0][k] for k in ('native_status', 'severity')) else 'changed'
            def brief(f):
                return {k:f[k] for k in ('id','revision','title','native_status','severity','category','tags','disposition','priority','notes','severity_override',*IDENTITY)}
            rows.append({'status':status,'before':[brief(f) for f in left],'after':[brief(f) for f in right]})
        result = {'id':uid(), 'before_id':before_id, 'after_id':after_id, 'rows':rows,
                  'warning':'Not observed does not mean resolved. Matching uses exact resource identity; unchanged means native status and severity agree, not identical evidence.'}
        with self.db.connect() as con:
            con.execute('INSERT INTO comparisons VALUES (?,?,?,?)', (result['id'], now(), json.dumps(result), 0))
        return result

    def carry(self, comparison_id):
        with self.db.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            row = con.execute('SELECT * FROM comparisons WHERE id=?', (comparison_id,)).fetchone()
            if not row: raise KeyError('Comparison not found')
            if row['applied']: raise ConflictError('Comparison already applied')
            preview = json.loads(row['snapshot'])
            pairs = [r for r in preview['rows'] if r['status']=='unchanged' and r['after'][0]['revision']==0]
            count = 0
            for pair in pairs:
                source, target = [decoded(con.execute('SELECT * FROM findings WHERE id=?',(pair[k][0]['id'],)).fetchone()) for k in ('before','after')]
                if source['revision'] != pair['before'][0]['revision'] or target['revision'] != 0:
                    raise ConflictError('Findings changed after comparison; create a new preview')
                # Deliberately do not carry report inclusion or report order.
                fields = ('category','tags','disposition','priority','notes','severity_override')
                if source['revision'] == 0: continue
                before = {k:target[k] for k in TRIAGE_FIELDS}
                after = {**before, **{k:source[k] for k in fields}}
                if before == after: continue
                values = [json.dumps(source[k]) if k=='tags' else source[k] for k in fields]
                con.execute('UPDATE findings SET '+','.join(k+'=?' for k in fields)+',revision=revision+1 WHERE id=?', [*values,target['id']])
                con.execute('INSERT INTO audit VALUES (?,?,?,?,?,?)', (uid(),target['id'],now(),'carry-forward:'+source['id'],json.dumps(before),json.dumps(after)))
                count += 1
            con.execute('UPDATE comparisons SET applied=1 WHERE id=?',(comparison_id,))
            con.execute('INSERT INTO workflow_audit VALUES (?,?,?,?)',(uid(),now(),'carry_forward',json.dumps({'comparison_id':comparison_id,'updated':count})))
        return {'updated':count}
