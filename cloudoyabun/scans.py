"""Small, explicit scan presets. No check lists or arbitrary extra arguments."""

import os
import hashlib
import math
from dataclasses import dataclass
from pathlib import Path

from .db import uid
from .execution import execute
from .service import MAX_IMPORT_BYTES, Service


@dataclass(frozen=True)
class ScanPlan:
    tool: str
    adapter: str | None
    command: list[str]
    version_command: list[str]
    output: Path
    success_codes: tuple[int, ...]

    def public(self):
        return {"tool": self.tool, "preset": "full", "adapter": self.adapter, "command": self.command,
                "version_command": self.version_command, "output": str(self.output), "success_codes": self.success_codes}


def plan_scan(tool, directory, *, provider=None, tenant=None, context=None, auth=None):
    directory = Path(directory).resolve()
    for name, value in (("provider", provider), ("tenant", tenant), ("context", context), ("auth", auth)):
        if value is not None and (not isinstance(value, str) or not value.strip() or value.startswith("-") or "\x00" in value):
            raise ValueError(f"Invalid {name}")
    if tool == "prowler":
        if provider not in ("aws", "azure", "gcp", "m365", "kubernetes"):
            raise ValueError("Prowler requires --provider aws, azure, gcp, m365, or kubernetes")
        if tenant:
            raise ValueError("--tenant is for AzureHound; Prowler uses the tenant in the configured credentials")
        if context and provider != "kubernetes":
            raise ValueError("--context applies only to Kubernetes")
        if auth and provider not in ("azure", "m365"):
            raise ValueError("--auth applies only to Prowler Azure or Microsoft 365")
        if auth not in (None, "cli", "env"):
            raise ValueError("--auth must be cli or env")
        command = ["prowler", provider, "--output-formats", "json-ocsf", "--output-directory", str(directory),
                   "--output-filename", "prowler", "--no-banner", "--no-color", "--verbose"]
        if provider in ("azure", "m365"):
            command.append("--sp-env-auth" if auth == "env" else "--az-cli-auth")
        if provider == "kubernetes":
            if not context:
                raise ValueError("Prowler Kubernetes requires --context to select the target cluster")
            command += ["--context", context]
        return ScanPlan(tool, "prowler-ocsf", command, ["prowler", "--version"], directory / "prowler.ocsf.json", (0, 3))
    if tool == "kubescape":
        if provider or tenant or auth:
            raise ValueError("Kubescape uses --context and kubeconfig credentials, not provider/tenant/auth options")
        if not context:
            raise ValueError("Kubescape requires --context to select the target cluster")
        output = directory / "kubescape.json"
        return ScanPlan(tool, "kubescape-json", ["kubescape", "scan", "framework", "all", "--kube-context", context,
                        "--format", "json", "--output", str(output), "--keep-local", "--verbose"],
                        ["kubescape", "version"], output, (0,))
    if tool == "azurehound":
        if provider or context or auth:
            raise ValueError("AzureHound uses --tenant and its native credential environment/configuration")
        if not tenant:
            raise ValueError("AzureHound requires --tenant")
        output = directory / "azurehound.json"
        return ScanPlan(tool, None, ["azurehound", "list", "--tenant", tenant, "--output", str(output),
                        "--verbosity", "1"], ["azurehound", "--version"], output, (0,))
    raise ValueError("Supported scan tools: prowler, kubescape, azurehound")


def run_scan(db, assessment_id, tool, *, timeout=7200, dry_run=False, callback=None, **options):
    service = Service(db)
    service.assessment(assessment_id)
    directory = db.path.parent / "runs" / uid()
    plan = plan_scan(tool, directory, **options)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Timeout must be positive")
    if dry_run:
        return {"plan": plan.public(), "dry_run": True}
    directory.mkdir(parents=True, mode=0o700)
    os.chmod(directory, 0o700)
    # Version checks run through the same bounded, redacted journal as scans.
    version_run = execute(db, assessment_id, tool, plan.version_command, timeout=15, callback=callback,
                          run_metadata={"purpose": "version-check"})
    if version_run["status"] != "succeeded":
        return {"run": version_run, "imports": [], "collections": [], "error": f"{tool} version check failed. Install the tool on PATH and inspect the execution log.", "output_directory": str(directory)}
    version_events = service.events(version_run["id"], source="stdout")
    version = "".join(e["details"].get("text", "") for e in version_events).strip()[:500] or "unreported"
    imports, collections = [], []

    def collect(run_id, journal, process_status):
        journal.emit("artifact_discovery", {"path": str(plan.output)}, step="collection")
        if not plan.output.is_file() or plan.output.is_symlink():
            journal.emit("artifact_missing", {"path": str(plan.output), "process_status": process_status}, step="collection", level="error")
            return "failed"
        plan.output.chmod(0o600)
        if plan.adapter is None:
            digest = hashlib.sha256()
            size = 0
            with plan.output.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            collection = {"path": str(plan.output), "sha256": digest.hexdigest(), "bytes": size,
                          "destination": "BloodHound", "process_status": process_status}
            collections.append(collection)
            journal.emit("collection_ready" if process_status == "succeeded" and size else "collection_incomplete",
                         collection, step="collection", level="info" if process_status == "succeeded" and size else "warning")
            return "succeeded" if size else "failed"
        # Output remains on disk for independent import/recovery, including
        # malformed/oversized output and files from failed or cancelled runs.
        with plan.output.open("rb") as source:
            content = source.read(MAX_IMPORT_BYTES + 1)
        if len(content) > MAX_IMPORT_BYTES:
            journal.emit("artifact_too_large", {"path": str(plan.output), "limit_bytes": MAX_IMPORT_BYTES,
                                               "retained_on_disk": True}, step="collection", level="error")
            return "failed"
        result = service.import_artifact(assessment_id, plan.output.name, content, plan.adapter, source_run_id=run_id)
        imports.append(result)
        journal.emit("artifact_imported", {"import_run_id": result["run"]["id"], "accepted": result["accepted"],
                                          "status": result["run"]["status"], "reused": result["reused"]}, step="collection")
        return result["run"]["status"]

    run = execute(db, assessment_id, tool, plan.command, timeout=timeout, callback=callback,
                  success_codes=plan.success_codes, postprocess=collect,
                  run_metadata={"adapter": plan.adapter, "preset": "full", "tool_version": version,
                                "version_run_id": version_run["id"]})
    return {"run": run, "imports": imports, "collections": collections, "output_directory": str(directory)}
