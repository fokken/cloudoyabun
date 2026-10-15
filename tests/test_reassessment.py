import json
import pytest
from cloudoyabun.reassessment import Reassessment
from cloudoyabun.ai import AIAssistance, Analysis, Area
from cloudoyabun import ai


def imports(service,assessment,content):
    first=service.import_artifact(assessment['id'],'before.json',content)
    records=json.loads(content)
    records[0]['test_new_export']=True
    second=service.import_artifact(assessment['id'],'after.json',json.dumps(records).encode())
    return first,second


def artifacts(service,assessment):
    return [a for a in Reassessment(service.db).artifacts() if a['assessment_id']==assessment['id']]


def test_carry_forward_and_conflicts(service,assessment,content):
    imports(service,assessment,content)
    a,b=artifacts(service,assessment)
    old=next(f for f in service.findings(assessment['id'])['items'] if f['artifact_id']==a['id'])
    service.triage(old['id'],{'notes':'Investigated','selected':True,'category':'storage'},0)
    repeat=Reassessment(service.db)
    preview=repeat.compare(a['id'],b['id'])
    assert all(r['status']=='unchanged' for r in preview['rows'])
    assert repeat.carry(preview['id'])['updated']==1
    target=next(f for f in service.findings(assessment['id'])['items'] if f['artifact_id']==b['id'] and f['rule_id']==old['rule_id'])
    detail=service.finding(target['id'])
    assert detail['notes']=='Investigated' and not detail['selected']
    assert detail['audit'][0]['actor']=='carry-forward:'+old['id']
    with pytest.raises(ValueError): repeat.carry(preview['id'])


def test_carry_atomic_stale_preview(service,assessment,content):
    imports(service,assessment,content)
    a,b=artifacts(service,assessment);repeat=Reassessment(service.db)
    preview=repeat.compare(a['id'],b['id'])
    source=preview['rows'][0]['before'][0]
    service.triage(source['id'],{'notes':'Changed since preview'},source['revision'])
    with pytest.raises(ValueError,match='changed'): repeat.carry(preview['id'])
    assert all(f['revision']==0 for f in service.findings(assessment['id'])['items'] if f['artifact_id']==b['id'])


def test_suppression_is_reversible_and_scoped(service,assessment,content):
    service.import_artifact(assessment['id'],'a.json',content)
    f=next(f for f in service.findings(assessment['id'])['items'] if f['asset'] and f['environment'])
    repeat=Reassessment(service.db)
    rule=repeat.suppress(f['id'],'Known lab exception')
    assert service.findings(assessment['id'],suppression='hide')['total']==5
    assert service.findings(assessment['id'],suppression='only')['total']==1
    assert service.finding(f['id'])['suppressed']
    assert service.finding(f['id'])['disposition']=='unreviewed'
    repeat.toggle(rule['id'],False)
    assert service.findings(assessment['id'],suppression='hide')['total']==6
    with pytest.raises(ValueError): repeat.suppress(f['id'],'expired','2000-01-01T00:00:00Z')


def test_native_batches_and_citations(service,assessment,content,monkeypatch):
    monkeypatch.setenv('CLOUDOYABUN_AI_MODEL','test')
    monkeypatch.setenv('CLOUDOYABUN_AI_BASE_URL','http://localhost:1234/v1')
    records=json.loads(content);records[0]['credentials']={'password':'do-not-send'}
    service.import_artifact(assessment['id'],'a.json',json.dumps(records).encode())
    assistant=AIAssistance(service.db)
    preview=assistant.prepare(assessment['id'],include_native=True,batch_size=2)
    assert 'do-not-send' not in json.dumps(preview['evidence'])
    assert preview['plan']['batches']==3
    calls=[]
    def provider(model,evidence,endpoint,protocol):
        calls.append(evidence)
        ids=[f['id'] for f in evidence] if isinstance(evidence,list) else [i for summary in evidence['batch_summaries'] for a in summary['areas'] for i in a['finding_ids']]
        return Analysis(areas=[Area(area='Review',summary='Evidence summary',priority=2,rationale='Check evidence',next_steps='Investigate',finding_ids=ids)],limitations='Selected evidence only'),{'total_tokens':10}
    monkeypatch.setattr(ai,'request_openai',provider)
    result=assistant.generate(assessment['id'],preview['id'])
    assert result['status']=='succeeded' and len(result['batches'])==3
    assert len(calls)==4 and result['usage']['total_tokens']==40
    assert len(result['result']['areas'][0]['finding_ids'])==6


def test_partial_ai_retains_batches(service,assessment,content,monkeypatch):
    monkeypatch.setenv('CLOUDOYABUN_AI_MODEL','test')
    monkeypatch.setenv('CLOUDOYABUN_AI_BASE_URL','http://localhost:1234/v1')
    service.import_artifact(assessment['id'],'a.json',content)
    assistant=AIAssistance(service.db);preview=assistant.prepare(assessment['id'],batch_size=2)
    count=0
    def provider(model,evidence,*args):
        nonlocal count
        count+=1
        if count==2: raise ValueError('offline')
        return Analysis(areas=[Area(area='Review',summary='Check',priority=2,rationale='Check',next_steps='Check',finding_ids=[evidence[0]['id']])],limitations='Partial'),{}
    monkeypatch.setattr(ai,'request_openai',provider)
    result=assistant.generate(assessment['id'],preview['id'])
    assert result['status']=='failed' and len(result['batches'])==1 and result['result']=={}


def test_comparison_changed_missing_and_ambiguous(service,assessment,content):
    service.import_artifact(assessment['id'],'before.json',content)
    before=artifacts(service,assessment)[0]['id']
    records=json.loads(content)
    records[0]['severity']='Critical'
    records.pop()
    service.import_artifact(assessment['id'],'after.json',json.dumps(records).encode())
    after=next(a['id'] for a in artifacts(service,assessment) if a['id']!=before)
    rows=Reassessment(service.db).compare(before,after)['rows']
    assert any(r['status']=='not-observed' for r in rows)
    # Change indexed severity directly to isolate comparison semantics from parser fixtures.
    with service.db.connect() as con:
        con.execute("UPDATE findings SET severity='Different' WHERE artifact_id=?",(after,))
    rows=Reassessment(service.db).compare(before,after)['rows']
    assert all(r['status'] in ('changed','not-observed') for r in rows)
    with service.db.connect() as con:
        con.execute('UPDATE findings SET environment=NULL WHERE artifact_id=?',(after,))
    assert any(r['status']=='ambiguous' for r in Reassessment(service.db).compare(before,after)['rows'])


def test_expired_and_other_environment_not_suppressed(service,assessment,content):
    service.import_artifact(assessment['id'],'a.json',content)
    f=service.findings(assessment['id'])['items'][0]
    repeat=Reassessment(service.db);rule=repeat.suppress(f['id'],'Lab exception',whole_check=True)
    with service.db.connect() as con:
        con.execute("UPDATE suppression_rules SET environment='other' WHERE id=?",(rule['id'],))
    assert not service.finding(f['id'])['suppressed']
    with service.db.connect() as con:
        con.execute("UPDATE suppression_rules SET environment=?,expires_at='2000-01-01T00:00:00.000+00:00' WHERE id=?",(f['environment'],rule['id']))
    assert not service.finding(f['id'])['suppressed']
