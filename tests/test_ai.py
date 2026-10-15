import json
import urllib.error
import pytest
from fastapi.testclient import TestClient
from cloudoyabun import ai
from cloudoyabun.api import create_app


@pytest.fixture
def prepared(service, assessment, content, monkeypatch):
    monkeypatch.setenv('CLOUDOYABUN_AI_BASE_URL', 'http://localhost:11434/v1')
    monkeypatch.setenv('CLOUDOYABUN_AI_MODEL', 'local-model')
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    service.import_artifact(assessment['id'], 'sample.json', content)
    ids = [f['id'] for f in service.findings(assessment['id'])['items']]
    assistant = ai.AIAssistance(service.db)
    return assistant, assistant.prepare(assessment['id'], ids)


def answer(evidence):
    return ai.Analysis(areas=[ai.Area(area='Identity', summary='Review this check', priority=3,
        rationale='Native status needs verification', next_steps='Inspect native evidence', finding_ids=[evidence[0]['id']])], limitations='Selected metadata only')


def test_preview_private_fields_and_isolation(prepared, service):
    assistant, item = prepared
    assert item['status'] == 'draft' and item['endpoint'].startswith('http://localhost')
    assert ai.configuration()['configured']
    assert all(not ({'payload', 'notes', 'asset', 'environment'} & f.keys()) for f in item['evidence'])
    other = service.create_assessment('Other', 'Other')
    with pytest.raises(ValueError): assistant.prepare(other['id'], [item['evidence'][0]['id']])
    with pytest.raises(KeyError): assistant.get(other['id'], item['id'])
    assert not assistant.history(other['id'])


def test_success_review_and_no_triage_mutation(prepared, service, monkeypatch):
    assistant, item = prepared
    before = service.findings(item['assessment_id'])
    monkeypatch.setattr(ai, 'request_openai', lambda model, evidence, endpoint, protocol: (answer(evidence), {'total_tokens': 50}))
    result = assistant.generate(item['assessment_id'], item['id'])
    assert result['status'] == 'succeeded' and result['usage']['total_tokens'] == 50
    assert service.findings(item['assessment_id']) == before
    assert service.run(result['run_id'])['status'] == 'succeeded'
    assert assistant.review(item['assessment_id'], item['id'], 'reviewed')['reviewed_at']
    with pytest.raises(ValueError): assistant.generate(item['assessment_id'], item['id'])


@pytest.mark.parametrize('failure', ['citation', 'network'])
def test_failure_is_logged_without_provider_secrets(prepared, service, monkeypatch, failure):
    assistant, item = prepared
    def provider(*args):
        if failure == 'network': raise RuntimeError('secret-provider-body')
        result = answer(item['evidence']); result.areas[0].finding_ids = ['foreign-id']
        return result, {}
    monkeypatch.setattr(ai, 'request_openai', provider)
    result = assistant.generate(item['assessment_id'], item['id'])
    assert result['status'] == 'failed' and result['result'] == {}
    assert 'secret-provider-body' not in json.dumps(result)
    assert service.run(result['run_id'])['status'] == 'failed'


def test_endpoint_change_requires_preview(prepared, monkeypatch):
    assistant, item = prepared
    monkeypatch.setenv('CLOUDOYABUN_AI_BASE_URL', 'http://localhost:9999/v1')
    with pytest.raises(ValueError, match='new preview'): assistant.generate(item['assessment_id'], item['id'])


def test_redaction():
    assert 'abc123' not in ai.scrub('token=abc123')


@pytest.mark.parametrize('protocol', ['chat', 'responses'])
def test_transport_contract(prepared, monkeypatch, protocol):
    _, item = prepared
    response_text = answer(item['evidence']).model_dump_json()
    payload = {'choices':[{'finish_reason':'stop','message':{'content':response_text}}]} if protocol == 'chat' else {'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':response_text}]}]}
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return json.dumps(payload).encode()
    class Opener:
        def open(self, request, timeout):
            assert request.full_url == 'http://localhost:11434/v1/' + ('responses' if protocol == 'responses' else 'chat/completions')
            assert request.get_header('Authorization') is None
            body = json.loads(request.data)
            assert body['model'] == 'local-model' and 'tools' not in body
            if protocol == 'responses': assert body['store'] is False
            return Response()
    monkeypatch.setattr(ai.urllib.request, 'build_opener', lambda *a: Opener())
    result, _ = ai.request_openai('local-model', item['evidence'], item['endpoint'], protocol)
    assert result.areas[0].priority == 3


def test_api_preview_and_session_protection(prepared, service):
    _, item = prepared
    with TestClient(create_app(service.db.path)) as client:
        path = '/api/assessments/' + item['assessment_id'] + '/ai'
        body = {'finding_ids':[item['evidence'][0]['id']]}
        assert client.post(path, json=body).status_code == 403
        headers = {'x-cloudoyabun-token':client.get('/api/session').json()['token']}
        response = client.post(path, json=body, headers=headers)
        assert response.status_code == 200 and response.json()['status'] == 'draft'
        assert client.get('/api/ai/config').json()['configured']


def test_no_default_endpoint_or_hosted_fallback(monkeypatch, prepared):
    assistant,item=prepared
    monkeypatch.delenv('CLOUDOYABUN_AI_BASE_URL',raising=False)
    monkeypatch.setenv('OPENAI_API_KEY','test-key-present')
    assert not ai.configuration()['configured']
    assert ai.configuration()['endpoint']=='No endpoint configured'
    called=[]
    monkeypatch.setattr(ai,'request_openai',lambda *args:called.append(args))
    with pytest.raises(ValueError,match='new preview'):
        assistant.generate(item['assessment_id'],item['id'])
    assert not called
