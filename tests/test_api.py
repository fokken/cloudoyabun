from fastapi.testclient import TestClient

from cloudoyabun.api import create_app


def test_http_import_triage_report_and_artifact(tmp_path, content):
    with TestClient(create_app(tmp_path / "app.sqlite3")) as client:
        assert client.get("/").status_code == 200
        assert client.get("/static/app.js").status_code == 200
        token = client.get("/api/session").json()["token"]
        client.headers["X-CloudOyabun-Token"] = token
        assessment = client.post("/api/assessments", json={"name": "API review", "scope": "Demo only"}).json()
        root = f"/api/assessments/{assessment['id']}"
        result = client.post(root + "/imports?filename=demo.json", content=content).json()
        assert result["accepted"] == 6
        item = client.get(root + "/findings").json()["items"][0]
        saved = client.patch(f"/api/findings/{item['id']}", json={"revision": 0, "selected": True, "category": "network"})
        assert saved.status_code == 200
        assert client.patch(f"/api/findings/{item['id']}", json={"revision": 0, "notes": "stale"}).status_code == 409
        assert client.get(f"/api/artifacts/{item['artifact_id']}").content == content
        report = client.post(root + "/reports").json()
        assert client.get(f"/api/reports/{report['id']}/download").text == report["content"]
        assert "import_completed" in client.get(f"/api/runs/{result['run']['id']}/logs").text


def test_local_api_rejects_cross_site_mutation_and_unknown_host(tmp_path):
    with TestClient(create_app(tmp_path / "app.sqlite3")) as client:
        assert client.post("/api/assessments", json={"name": "attack", "scope": "x"}).status_code == 403
        assert client.get("/api/session", headers={"host": "untrusted.example"}).status_code == 400
        response = client.get("/")
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_api_validation_and_missing_records(tmp_path):
    with TestClient(create_app(tmp_path / "app.sqlite3")) as client:
        client.headers["X-CloudOyabun-Token"] = client.get("/api/session").json()["token"]
        assert client.get("/api/findings/missing").status_code == 404
        assert client.post("/api/assessments", json={"name": " ", "scope": " "}).status_code == 400
        assert client.patch("/api/findings/missing", json={"revision": 0, "payload": {}}).status_code == 422
