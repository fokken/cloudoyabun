import pytest


def test_override_filter_group_report_and_reset(service,assessment,content):
    service.import_artifact(assessment['id'],'a.json',content)
    f=service.findings(assessment['id'])['items'][0]
    original=service.finding(f['id'])
    changed=service.triage(f['id'],{'severity_override':'Critical','selected':True},0)
    assert changed['severity']==original['severity'] and changed['payload']==original['payload']
    assert changed['effective_severity']=='Critical'
    assert f['id'] in [r['id'] for r in service.findings(assessment['id'],severity='Critical')['items']]
    assert 'Critical' in service.overview(assessment['id'])['facets']['severity']
    group=next(g for g in service.findings(assessment['id'],grouped=True)['items'] if g['rule_id']==f['rule_id'])
    assert group['severity']=='Critical' and group['override_count']==1
    report=service.create_report(assessment['id'])
    assert 'Severity: Critical (analyst override)' in report['content']
    assert 'Native severity: '+original['severity'] in report['content']
    service.bulk_triage(assessment['id'],[{'id':f['id'],'revision':1}],{'severity_override':None})
    reset=service.finding(f['id'])
    assert reset['effective_severity']==original['severity'] and reset['severity_override'] is None
    assert reset['audit'][-1]['after_state']['severity_override'] is None
    assert service.report(report['id'])['content']==report['content']


@pytest.mark.parametrize('value',['', 'Bogus', 2])
def test_invalid_override(service,assessment,content,value):
    service.import_artifact(assessment['id'],'a.json',content)
    f=service.findings(assessment['id'])['items'][0]
    with pytest.raises(ValueError): service.triage(f['id'],{'severity_override':value},0)
    with pytest.raises(ValueError): service.bulk_triage(assessment['id'],[{'id':f['id'],'revision':0}],{'severity_override':value})
    assert service.finding(f['id'])['revision']==0
