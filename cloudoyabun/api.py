"""Local-only web API and bundled analyst UI."""

import os
import secrets
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .db import Database
from .service import ConflictError, MAX_IMPORT_BYTES, Service


class ComparisonInput(BaseModel):
    before_id: str
    after_id: str


class SuppressionInput(BaseModel):
    finding_id: str
    reason: str = Field(min_length=1,max_length=2000)
    expires_at: str | None = None
    whole_check: bool = False


class SuppressionToggle(BaseModel):
    enabled: bool


class AIInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    finding_ids: list[str] | None = Field(default=None, min_length=1, max_length=2000)
    category: str = Field(default='', max_length=100)
    include_native: bool = False
    batch_size: int = Field(default=25, ge=1, le=100)


class AIReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    status: str


class AssessmentInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    scope: str = Field(min_length=1, max_length=10000)


class TriageInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    revision: int
    severity_override: str | None = None
    category: str | None = None
    tags: list[str] | None = None
    disposition: str | None = None
    priority: int | None = None
    notes: str | None = None
    selected: bool | None = None
    report_order: int | None = None


class FindingTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    revision: int = Field(ge=0)


class BulkTriageInput(BaseModel):
    severity_override: str | None = None
    notes: str | None = Field(default=None, max_length=20000)
    notes_mode: str | None = None
    selected: bool | None = None
    model_config = ConfigDict(extra="forbid", strict=True)
    targets: list[FindingTarget] = Field(min_length=1, max_length=1000)
    category: str | None = Field(default=None, max_length=100)
    disposition: str | None = None


class BulkTagsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    targets: list[FindingTarget] = Field(min_length=1, max_length=1000)
    tags: list[str] = Field(min_length=1, max_length=50)
    mode: str = "add"


def create_app(db_path=None):
    db = Database(db_path or os.environ.get("CLOUDOYABUN_DB", ".cloudoyabun/cloudoyabun.sqlite3"))
    service = Service(db)
    app = FastAPI(title="CloudOyabun", version="0.1.0", docs_url=None, redoc_url=None)
    app.state.service = service
    token = secrets.token_urlsafe(32)
    app.state.csrf_token = token
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])

    @app.middleware("http")
    async def local_security(request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            supplied = request.headers.get("x-cloudoyabun-token", "")
            if not secrets.compare_digest(supplied, token):
                return JSONResponse({"detail": "Missing or invalid local session token. Reload the app."}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(KeyError)
    async def not_found(request, exc):
        return JSONResponse({"detail": "Record not found"}, status_code=404)

    @app.exception_handler(ValueError)
    async def bad_input(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409 if isinstance(exc, ConflictError) else 400)

    @app.get("/api/session")
    def session():
        return {"token": token, "version": "0.1.0"}

    @app.get("/api/assessments")
    def assessments():
        return service.assessments()

    @app.post("/api/assessments", status_code=201)
    def create_assessment(data: AssessmentInput):
        return service.create_assessment(data.name, data.scope)

    @app.get("/api/assessments/{assessment_id}/overview")
    def overview(assessment_id: str):
        return service.overview(assessment_id)

    @app.post("/api/assessments/{assessment_id}/imports")
    async def import_results(assessment_id: str, request: Request, filename: str = "upload.json", adapter: str = "auto"):
        content = bytearray()
        async for chunk in request.stream():
            content.extend(chunk)
            if len(content) > MAX_IMPORT_BYTES:
                return JSONResponse({"detail": "Import exceeds the 25 MiB limit"}, status_code=413)
        return await run_in_threadpool(service.import_artifact, assessment_id, filename, bytes(content), adapter)

    @app.get("/api/assessments/{assessment_id}/findings")
    def findings(assessment_id: str, q: str = "", sort: str = "title", direction: str = "asc",
                 offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                 tool: str = "", provider: str = "", environment: str = "", category: str = "", severity: str = "",
                 suppression: str = "", native_status: str = "", disposition: str = "", service_name: str = "", run_id: str = "",
                 tag: str = "", selected: bool | None = None, grouped: bool = False, group_key: str = ""):
        return service.findings(assessment_id, q=q, sort=sort, direction=direction, offset=offset, limit=limit,
                                tool=tool, provider=provider, environment=environment, category=category, severity=severity,
                                native_status=native_status, disposition=disposition, service=service_name, run_id=run_id, tag=tag, selected=selected,
                                grouped=grouped, group_key=group_key, suppression=suppression)

    @app.post("/api/assessments/{assessment_id}/bulk-tags")
    def bulk_tags(assessment_id: str, data: BulkTagsInput):
        return service.bulk_tags(assessment_id, [t.model_dump() for t in data.targets], data.tags, data.mode)

    @app.post("/api/assessments/{assessment_id}/bulk-triage")
    def bulk_triage(assessment_id: str, data: BulkTriageInput):
        return service.bulk_triage(assessment_id, [t.model_dump() for t in data.targets],
                                   data.model_dump(exclude_unset=True, exclude={"targets"}))

    @app.get("/api/findings/{finding_id}")
    def finding(finding_id: str):
        return service.finding(finding_id)

    @app.patch("/api/findings/{finding_id}")
    def triage(finding_id: str, data: TriageInput):
        return service.triage(finding_id, data.model_dump(exclude_unset=True, exclude={"revision"}), data.revision)

    @app.get("/api/artifacts/{artifact_id}")
    def artifact(artifact_id: str):
        item = service.artifact(artifact_id)
        return Response(item["content"], media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{artifact_id}.json"'})

    @app.get("/api/assessments/{assessment_id}/runs")
    def runs(assessment_id: str):
        return service.runs(assessment_id)

    @app.get("/api/runs/{run_id}/events")
    def events(run_id: str, after: int = Query(0, ge=0), source: str = "", level: str = "", event_type: str = "", q: str = ""):
        return service.events(run_id, after=after, source=source, level=level, event_type=event_type, q=q)

    @app.get("/api/runs/{run_id}/logs")
    def logs(run_id: str):
        import json
        from fastapi.responses import StreamingResponse
        service.run(run_id)

        def stream():
            after = 0
            while True:
                rows = service.events(run_id, after=after, limit=1000)
                if not rows:
                    break
                for row in rows:
                    yield json.dumps(row) + "\n"
                after = rows[-1]["seq"]
        return StreamingResponse(stream(), media_type="application/x-ndjson", headers={"Content-Disposition": f'attachment; filename="{run_id}.ndjson"'})

    @app.get("/api/assessments/{assessment_id}/reports")
    def reports(assessment_id: str):
        return service.reports(assessment_id)

    @app.post("/api/assessments/{assessment_id}/reports", status_code=201)
    def create_report(assessment_id: str):
        return service.create_report(assessment_id)

    @app.get("/api/reports/{report_id}/download")
    def download_report(report_id: str):
        return Response(service.report(report_id)["content"], media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="cloudoyabun-{report_id}.md"'})

    from .reassessment import Reassessment
    repeat = Reassessment(db)

    @app.get('/api/reassessment/artifacts')
    def comparison_artifacts():
        return repeat.artifacts()

    @app.post('/api/reassessment/compare')
    def compare(data: ComparisonInput):
        return repeat.compare(data.before_id, data.after_id)

    @app.post('/api/reassessment/{comparison_id}/carry')
    def carry(comparison_id: str):
        return repeat.carry(comparison_id)

    @app.get('/api/suppressions')
    def suppressions():
        return repeat.rules()

    @app.post('/api/suppressions')
    def suppress(data: SuppressionInput):
        return repeat.suppress(**data.model_dump())

    @app.patch('/api/suppressions/{rule_id}')
    def toggle_suppression(rule_id: str, data: SuppressionToggle):
        return repeat.toggle(rule_id,data.enabled)

    from .ai import AIAssistance, configuration
    ai = AIAssistance(db)

    @app.get("/api/ai/config")
    def ai_config():
        return configuration()

    @app.get("/api/assessments/{assessment_id}/ai")
    def ai_history(assessment_id: str):
        return ai.history(assessment_id)

    @app.post("/api/assessments/{assessment_id}/ai")
    def ai_prepare(assessment_id: str, data: AIInput):
        return ai.prepare(assessment_id, **data.model_dump())

    @app.get("/api/assessments/{assessment_id}/ai/{analysis_id}")
    def ai_detail(assessment_id: str, analysis_id: str):
        return ai.get(assessment_id, analysis_id)

    @app.post("/api/assessments/{assessment_id}/ai/{analysis_id}/generate")
    def ai_generate(assessment_id: str, analysis_id: str):
        return ai.generate(assessment_id, analysis_id)

    @app.patch("/api/assessments/{assessment_id}/ai/{analysis_id}")
    def ai_review(assessment_id: str, analysis_id: str, data: AIReviewInput):
        return ai.review(assessment_id, analysis_id, data.status)

    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(static / "index.html")

    return app
