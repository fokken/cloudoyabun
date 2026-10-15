import pytest
from fastapi.testclient import TestClient
from cloudoyabun.api import create_app


def selected(service, assessment, content):
    service.import_artifact(assessment['id'], 'demo.json', content)
    return [{'id': f['id'], 'revision': f['revision']} for f in service.findings(assessment['id'])['items']][:2]


def test_bulk_decisions_preserve_evidence_and_audit(service, assessment, content):
    targets=selected(service,assessment,content)
    before=[service.finding(t['id']) for t in targets]
    assert service.bulk_triage(assessment['id'],targets,{'category':' network ', 'disposition':'confirmed'})['updated']==2
    for previous in before:
        current=service.finding(previous['id'])
        assert current['category']=='network' and current['disposition']=='confirmed'
        for field in ('payload','tags','notes','selected','priority','report_order'):
            assert current[field]==previous[field]
        assert current['revision']==1 and len(current['audit'])==1
    fresh=[{'id':t['id'],'revision':1} for t in targets]
    assert service.bulk_triage(assessment['id'],fresh,{'category':'network'})['updated']==0
    assert service.bulk_triage(assessment['id'],fresh,{'category':''})['updated']==2
    assert service.finding(targets[0]['id'])['disposition']=='confirmed'


def test_stale_and_foreign_targets_roll_back(service,assessment,content):
    targets=selected(service,assessment,content)
    service.triage(targets[1]['id'],{'notes':'changed'},0)
    with pytest.raises(ValueError,match='changed'):
        service.bulk_triage(assessment['id'],targets,{'disposition':'noise'})
    assert service.finding(targets[0]['id'])['revision']==0
    other=service.create_assessment('Other','Other')
    with pytest.raises(KeyError): service.bulk_triage(other['id'],targets,{'category':'network'})


@pytest.mark.parametrize('changes',[{}, {'priority':4}, {'category':None}, {'category':'x'*101}, {'disposition':'bogus'}, {'disposition':None}])
def test_invalid_changes(service,assessment,content,changes):
    targets=selected(service,assessment,content)
    with pytest.raises(ValueError): service.bulk_triage(assessment['id'],targets,changes)
    assert service.finding(targets[0]['id'])['revision']==0


def test_api_bulk_decisions(service,assessment,content):
    targets=selected(service,assessment,content)
    with TestClient(create_app(service.db.path)) as client:
        url='/api/assessments/'+assessment['id']+'/bulk-triage'
        assert client.post(url,json={'targets':targets,'disposition':'noise'}).status_code==403
        client.headers['x-cloudoyabun-token']=client.get('/api/session').json()['token']
        assert client.post(url,json={'targets':targets,'category':'storage','disposition':'noise'}).json()['updated']==2
        assert client.post(url,json={'targets':targets,'disposition':'confirmed'}).status_code==409
        assert client.post(url,json={'targets':[],'category':'storage'}).status_code==422


def test_bulk_report_inclusion_and_snapshot(service,assessment,content):
    targets=selected(service,assessment,content)
    assert service.bulk_triage(assessment['id'],targets,{'selected':True})['updated']==2
    report=service.create_report(assessment['id'])
    assert report['finding_count']==2
    for target in targets:
        finding=service.finding(target['id'])
        assert finding['selected'] and finding['audit'][-1]['after_state']['selected']
    fresh=[{'id':t['id'],'revision':1} for t in targets]
    assert service.bulk_triage(assessment['id'],fresh,{'selected':False,'category':'network'})['updated']==2
    assert service.findings(assessment['id'],selected=True)['total']==0
    assert service.report(report['id'])['content']==report['content']


@pytest.mark.parametrize('selected_value',[None,1,'true'])
def test_bulk_report_rejects_non_boolean(service,assessment,content,selected_value):
    targets=selected(service,assessment,content)
    with pytest.raises(ValueError): service.bulk_triage(assessment['id'],targets,{'selected':selected_value})


def test_bulk_notes_modes_and_overflow_rollback(service,assessment,content):
    targets=selected(service,assessment,content)
    service.bulk_triage(assessment['id'],targets,{'notes_mode':'append','notes':'First','selected':True})
    targets=[{'id':t['id'],'revision':1} for t in targets]
    service.bulk_triage(assessment['id'],targets,{'notes_mode':'append','notes':'Next'})
    assert service.finding(targets[0]['id'])['notes']=='First\n\nNext'
    targets=[{'id':t['id'],'revision':2} for t in targets]
    service.bulk_triage(assessment['id'],targets,{'notes_mode':'replace','notes':'Replacement'})
    targets=[{'id':t['id'],'revision':3} for t in targets]
    service.triage(targets[1]['id'],{'notes':'x'*20000},3)
    targets[1]['revision']=4
    with pytest.raises(ValueError,match='exceed'):
        service.bulk_triage(assessment['id'],targets,{'notes_mode':'append','notes':'extra','selected':False})
    assert service.finding(targets[0]['id'])['notes']=='Replacement'
    assert service.finding(targets[0]['id'])['selected']
    service.bulk_triage(assessment['id'],targets,{'notes_mode':'clear'})
    assert all(service.finding(t['id'])['notes']=='' for t in targets)
