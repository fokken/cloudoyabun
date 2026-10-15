import copy
import json

import pytest
from fastapi.testclient import TestClient

from cloudoyabun.api import create_app
from cloudoyabun.service import ConflictError


@pytest.mark.parametrize("severities,expected", [
    (["High", "High"], "High"),
    (["High", "Low"], "Mixed"),
    ([None, None], None),
    (["High", None], "Mixed"),
])
def test_group_severity_uses_all_matching_records(service, assessment, record, severities, expected):
    records = []
    for severity in severities:
        item = copy.deepcopy(record)
        item["severity"] = severity
        records.append(item)
    service.import_artifact(assessment["id"], "severity.json", json.dumps(records).encode())
    group = service.findings(assessment["id"], grouped=True, limit=1)["items"][0]
    assert group["severity"] == expected
    assert set(group["severities"]) == set(severities)
    if "High" in severities:
        filtered = service.findings(assessment["id"], grouped=True, severity="High")["items"][0]
        assert filtered["severity"] == "High"


def test_grouping_precedes_pagination_and_retains_children(service, assessment, record):
    records = []
    for i in range(65):
        child = copy.deepcopy(record)
        child['resources'][0]['uid'] = f'resource-{i}'
        child['status_code'] = 'PASS' if i == 0 else 'FAIL'
        records.append(child)
    service.import_artifact(assessment['id'], 'many.json', json.dumps(records).encode())
    groups = service.findings(assessment['id'], grouped=True, limit=1)
    assert groups['total'] == 1 and groups['items'][0]['count'] == 65
    key = groups['items'][0]['group_key']
    first = service.findings(assessment['id'], group_key=key)
    second = service.findings(assessment['id'], group_key=key, offset=50)
    assert len(first['items']) == 50 and len(second['items']) == 15
    assert len({f['id'] for f in first['items'] + second['items']}) == 65
    filtered = service.findings(assessment['id'], grouped=True, native_status='FAIL')
    assert filtered['items'][0]['count'] == 64
    assert service.findings(assessment['id'], group_key=key, native_status='FAIL')['total'] == 64


def test_group_identity_and_missing_check_ids(service, assessment, record):
    records = [copy.deepcopy(record) for _ in range(5)]
    records[1]['cloud']['provider'] = 'azure'
    records[2]['metadata']['event_code'] = 'other-check'
    del records[3]['metadata']['event_code']
    del records[4]['metadata']['event_code']
    service.import_artifact(assessment['id'], 'groups.json', json.dumps(records).encode())
    assert service.findings(assessment['id'], grouped=True)['total'] == 5
    # Different tools with the same rule ID must not share a heading.
    f = service.findings(assessment['id'])['items'][0]
    with service.db.connect() as con:
        con.execute('UPDATE findings SET tool=? WHERE id=?', ('other-tool', f['id']))
    assert service.findings(assessment['id'], grouped=True)['total'] == 5


def test_bulk_add_remove_preserves_evidence_and_audits(service, assessment, content):
    service.import_artifact(assessment['id'], 'input.json', content)
    items = service.findings(assessment['id'])['items'][:2]
    original = service.finding(items[0]['id'])['payload']
    service.triage(items[0]['id'], {'tags': ['keep']}, 0)
    targets = [{'id': f['id'], 'revision': 1 if i == 0 else 0} for i, f in enumerate(items)]
    result = service.bulk_tags(assessment['id'], targets, [' review ', 'review'])
    assert result['updated'] == 2
    assert service.finding(items[0]['id'])['tags'] == ['keep', 'review']
    assert service.finding(items[1]['id'])['tags'] == ['review']
    for target in targets:
        target['revision'] += 1
    service.bulk_tags(assessment['id'], targets, ['review'], mode='remove')
    f = service.finding(items[0]['id'])
    assert f['tags'] == ['keep'] and f['payload'] == original
    assert len(f['audit']) == 3


def test_bulk_conflict_rolls_back_every_record(service, assessment, content):
    service.import_artifact(assessment['id'], 'input.json', content)
    items = service.findings(assessment['id'])['items'][:2]
    service.triage(items[1]['id'], {'notes': 'Concurrent review'}, 0)
    targets = [{'id': f['id'], 'revision': 0} for f in items]
    with pytest.raises(ConflictError):
        service.bulk_tags(assessment['id'], targets, ['new'])
    first = service.finding(items[0]['id'])
    assert first['tags'] == [] and first['revision'] == 0 and first['audit'] == []


def test_bulk_rejects_cross_assessment_and_invalid_operations(service, assessment, content):
    service.import_artifact(assessment['id'], 'input.json', content)
    target = {'id': service.findings(assessment['id'])['items'][0]['id'], 'revision': 0}
    other = service.create_assessment('Other', 'Other scope')
    with pytest.raises(KeyError):
        service.bulk_tags(other['id'], [target], ['test'])
    for targets, tags, mode in [([target, target], ['x'], 'add'), ([target], [' '], 'add'), ([target], ['x'], 'replace'), ([target], ['x'*101], 'add')]:
        with pytest.raises(ValueError):
            service.bulk_tags(assessment['id'], targets, tags, mode)


def test_http_group_and_bulk_contract(tmp_path, content):
    with TestClient(create_app(tmp_path / 'api.sqlite3')) as client:
        client.headers['X-CloudOyabun-Token'] = client.get('/api/session').json()['token']
        assessment = client.post('/api/assessments', json={'name':'Bulk', 'scope':'Synthetic'}).json()
        root = f"/api/assessments/{assessment['id']}"
        client.post(root + '/imports', content=content)
        group = client.get(root + '/findings?grouped=true').json()['items'][0]
        children = client.get(root + '/findings', params={'group_key':group['group_key']}).json()['items']
        targets = [{'id': f['id'], 'revision': f['revision']} for f in children]
        response = client.post(root + '/bulk-tags', json={'targets':targets, 'tags':['bulk']})
        assert response.status_code == 200 and response.json()['updated'] == len(targets)
        assert client.post(root + '/bulk-tags', json={'targets':targets, 'tags':['stale']}).status_code == 409
        assert client.post(root + '/bulk-tags', json={'targets':[], 'tags':['invalid']}).status_code == 422
