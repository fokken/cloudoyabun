"""Command line entry point for local assessments and explicit execution."""

import argparse
import json
import os
import sys
from pathlib import Path

from .db import Database
from .service import MAX_IMPORT_BYTES, Service


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cloudoyabun", description="Cloud security assessment workbench")
    parser.add_argument("--db", default=os.environ.get("CLOUDOYABUN_DB", ".cloudoyabun/cloudoyabun.sqlite3"))
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("init", help="Initialize the local database")
    create = sub.add_parser("create", help="Create an assessment")
    create.add_argument("name")
    create.add_argument("--scope", required=True)
    sub.add_parser("assessments", help="List assessments")
    ingest = sub.add_parser("import", help="Import independently collected Prowler or Kubescape JSON")
    ingest.add_argument("assessment")
    ingest.add_argument("file", type=Path)
    ingest.add_argument("--tool", choices=("auto", "prowler", "kubescape"), default="auto")
    scan = sub.add_parser("scan", help="Run a predefined full scan or AzureHound collection")
    scan.add_argument("tool", choices=("prowler", "kubescape", "azurehound"))
    scan.add_argument("--assessment", required=True)
    scan.add_argument("--provider", choices=("aws", "azure", "gcp", "m365", "kubernetes"))
    scan.add_argument("--tenant", help="AzureHound target tenant")
    scan.add_argument("--context", help="Kubernetes target context")
    scan.add_argument("--auth", choices=("cli", "env"), help="Prowler Azure/M365: existing CLI login (default) or service-principal environment")
    scan.add_argument("--timeout", type=float, default=7200, help="Scan timeout in seconds (default: 7200)")
    scan.add_argument("--dry-run", action="store_true", help="Show the command without executing anything")
    findings = sub.add_parser("findings", help="List findings")
    findings.add_argument("assessment")
    findings.add_argument("--query", default="")
    findings.add_argument("--sort", default="title")
    findings.add_argument("--offset", default=0, type=int)
    triage = sub.add_parser("triage", help="Update analyst fields; JSON object and revision required")
    triage.add_argument("finding")
    triage.add_argument("--revision", required=True, type=int)
    triage.add_argument("--set", required=True, dest="changes", help='JSON object, e.g. {"selected":true,"category":"storage"}')
    report = sub.add_parser("report", help="Freeze selected findings in a Markdown report")
    report.add_argument("assessment")
    report.add_argument("--output", type=Path, required=True)
    runs = sub.add_parser("runs", help="List import and execution runs")
    runs.add_argument("assessment")
    logs = sub.add_parser("logs", help="Export run events as NDJSON")
    logs.add_argument("run")
    logs.add_argument("--source", default="")
    logs.add_argument("--level", default="")
    run = sub.add_parser("run", help="Execute an explicitly supplied command with granular logging")
    run.add_argument("--assessment", required=True)
    run.add_argument("--tool", required=True)
    run.add_argument("--timeout", type=float, default=300)
    run.add_argument("--retries", type=int, default=0)
    run.add_argument("--redact-env", action="append", default=[], metavar="VARIABLE")
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- executable arguments")
    serve = sub.add_parser("serve", help="Open the local analyst web service")
    serve.add_argument("--port", type=int, default=8787)
    sub.add_parser("demo", help="Create an explicitly labeled synthetic assessment; does not scan anything")
    args = parser.parse_args(argv)
    try:
        db = Database(args.db)
        service = Service(db)
        result = None
        if args.action == "init":
            result = {"database": str(db.path), "schema_version": 5}
        elif args.action == "create":
            result = service.create_assessment(args.name, args.scope)
        elif args.action == "assessments":
            result = service.assessments()
        elif args.action == "import":
            with args.file.open("rb") as source:
                content = source.read(MAX_IMPORT_BYTES + 1)
            adapter = {"auto": "auto", "prowler": "prowler-ocsf", "kubescape": "kubescape-json"}[args.tool]
            result = service.import_artifact(args.assessment, args.file.name, content, adapter)
        elif args.action == "findings":
            result = service.findings(args.assessment, q=args.query, sort=args.sort, offset=args.offset)
        elif args.action == "triage":
            changes = json.loads(args.changes)
            if not isinstance(changes, dict):
                raise ValueError("--set must contain a JSON object")
            result = service.triage(args.finding, changes, args.revision)
        elif args.action == "runs":
            result = service.runs(args.assessment)
        elif args.action == "logs":
            after = 0
            while True:
                rows = service.events(args.run, after=after, source=args.source, level=args.level, limit=1000)
                if not rows:
                    break
                for row in rows:
                    print(json.dumps(row))
                after = rows[-1]["seq"]
            return 0
        elif args.action == "report":
            result = service.create_report(args.assessment)
            args.output.write_text(result.pop("content"), encoding="utf-8")
            result["output"] = str(args.output.resolve())
        elif args.action in ("run", "scan"):
            from .execution import execute
            import signal

            def interrupted(signum, frame):
                raise KeyboardInterrupt

            previous = signal.signal(signal.SIGTERM, interrupted)
            try:
                callback = lambda event: print(json.dumps(event), file=sys.stderr, flush=True)
                if args.action == "scan":
                    from .scans import run_scan
                    result = run_scan(db, args.assessment, args.tool, timeout=args.timeout, dry_run=args.dry_run,
                                      provider=args.provider, tenant=args.tenant, context=args.context, auth=args.auth, callback=callback)
                else:
                    command = args.command[1:] if args.command[:1] == ["--"] else args.command
                    result = execute(db, args.assessment, args.tool, command, timeout=args.timeout, retries=args.retries,
                                     redact_env=args.redact_env, callback=callback)
            finally:
                signal.signal(signal.SIGTERM, previous)
        elif args.action == "serve":
            import uvicorn
            from .api import create_app
            uvicorn.run(create_app(db.path), host="127.0.0.1", port=args.port)
            return 0
        elif args.action == "demo":
            assessment = service.create_assessment("Northstar / synthetic demo", "Synthetic example resources only. No cloud account has been contacted or assessed.")
            content = (Path(__file__).parent / "fixtures" / "demo.ocsf.json").read_bytes()
            imported = service.import_artifact(assessment["id"], "synthetic-demo.ocsf.json", content)
            result = {"assessment": assessment, "import": imported}
        print(json.dumps(result, indent=2))
        if isinstance(result, dict):
            status = result.get("run", result).get("status")
            if status in ("failed", "partial", "timed-out", "cancelled", "interrupted"):
                return 1
        return 0
    except (ValueError, KeyError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
