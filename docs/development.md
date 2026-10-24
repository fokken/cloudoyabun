# Working with CloudOyabun

## Implementation map

| Path | Responsibility |
| --- | --- |
| `cloudoyabun/db.py` | SQLite schema, connections, and identifiers |
| `cloudoyabun/service.py` | Assessment, import, triage, filtering, and report services |
| `cloudoyabun/archive.py` | Portable per-scan export and restore |
| `cloudoyabun/integrations/` | Parser registry and tool-specific metadata extraction |
| `cloudoyabun/events.py` | Incrementally committed structured event journal |
| `cloudoyabun/execution.py` | POSIX subprocess runner and durable execution journal |
| `cloudoyabun/scans.py` | Predefined scans, version probes, and output collection |
| `cloudoyabun/cli.py` | CLI commands, also available through `python -m cloudoyabun` |
| `cloudoyabun/api.py` | Local HTTP API and UI serving |
| `cloudoyabun/static/` | Browser workbench with no frontend build step |
| `tests/` | Service, API, and process integration tests |

The database defaults to `.cloudoyabun/cloudoyabun.sqlite3`. Set `CLOUDOYABUN_DB` or pass `--db PATH` before the CLI subcommand to override it. The demo uses a separate database when following the README. Database files and the virtual environment are ignored by Git.

## CLI workflow

Create an assessment and copy its returned ID:

```sh
.venv/bin/python -m cloudoyabun create "Production review" --scope "Approved account IDs and assessment boundaries"
.venv/bin/python -m cloudoyabun assessments
.venv/bin/python -m cloudoyabun import ASSESSMENT_ID /path/to/prowler-output.ocsf.json
.venv/bin/python -m cloudoyabun findings ASSESSMENT_ID --query bucket --sort title
```

Use the returned finding ID and revision to record a decision:

```sh
.venv/bin/python -m cloudoyabun triage FINDING_ID --revision 0 --set '{"category":"storage","tags":["follow-up"],"disposition":"confirmed","priority":3,"selected":true,"notes":"Analyst investigation notes"}'
.venv/bin/python -m cloudoyabun report ASSESSMENT_ID --output technical-report.md
.venv/bin/python -m cloudoyabun scan-archives ASSESSMENT_ID
.venv/bin/python -m cloudoyabun export-scan ARTIFACT_ID --output scan.zip
.venv/bin/python -m cloudoyabun restore-scan scan.zip
.venv/bin/python -m cloudoyabun retry-import FAILED_IMPORT_RUN_ID
```

Each successful edit increments `revision`. A stale edit fails rather than overwriting another decision. Priority ranges from 0 (unset) to 4 (highest). Native severity remains a tool-owned value; current severity sorting is alphabetical and does not imply a universal severity ranking.

### Check groups and bulk tagging

The workbench defaults to **Group by check**. Within the current assessment, matching tool, provider, and native check ID share an expandable heading. Grouping covers the full filtered result set before pagination, including records from different environments and runs. Findings without a check ID remain separate. Group headings show matching record counts, not unique asset counts. Group sorting uses the minimum value of the selected sort field across matching children; each child's own severity and disposition remain visible on expansion.

Expand a heading to browse its individual findings, including environment and run references. Children load 50 at a time with **Load more findings**. Turn grouping off for a flat table. This is a display grouping only: native records, analyst decisions, and report entries remain individually addressable.

Use row checkboxes or **Select displayed findings** to build a temporary bulk selection. The header checkbox selects currently displayed records; collapsed groups and unloaded children are excluded. Selection carries across pages and view-mode changes; changing filters or assessments clears it. The bulk bar adds or removes comma-separated tags for up to 1000 selected findings without replacing unrelated tags. Report inclusion remains a separate analyst field.

Bulk changes validate every selected revision in one transaction, reject cross-assessment targets, and record each changed finding in its decision history. A stale target, invalid tag list, or resulting tag limit violation rolls back the whole batch. Existing report snapshots remain unchanged.

### Execution and logs

Run an explicitly supplied executable and arguments; the runner does not invoke a shell. This harmless example only demonstrates output capture:

```sh
.venv/bin/python -m cloudoyabun run --assessment ASSESSMENT_ID --tool diagnostic --timeout 30 -- python3 -c 'import sys; print("stdout example"); print("stderr example", file=sys.stderr)'
.venv/bin/python -m cloudoyabun runs ASSESSMENT_ID
.venv/bin/python -m cloudoyabun logs RUN_ID
.venv/bin/python -m cloudoyabun logs RUN_ID --source stderr
```

Execution emits NDJSON events to stderr as they are committed, followed by the final run record on stdout. The browser's **Execution log** view can inspect the same persisted events and export NDJSON. The stream includes sequence, UTC timestamp, elapsed milliseconds, step, attempt, source, level, type, and details. Wrapper events report process activity; internal tool activity is visible only if the tool emits it.

Retries are opt-in (`--retries 1`, maximum 3). An attempt uses a 300-second default timeout, configurable with `--timeout`. Ctrl+C or SIGTERM cancels and terminates the process group. A generic command succeeds only on exit code 0; the predefined Prowler adapter additionally accepts exit code 3 as a completed scan with failed checks.

Output capture is limited to 5 MiB per run, across all attempts and streams. Excess output is drained but discarded with an explicit `output_truncated` event. The output limit does not suppress lifecycle events. Stdout and stderr retain separate identities; their collected order is not guaranteed to match the tool's internal write order.

Known secret values from environment variables whose names include secret/token/password/API-key/access-key patterns, and similarly named command options, are redacted before logging. Supply `--redact-env VARIABLE_NAME` for other environment-held secret values. Redaction handles secrets split across stream chunks. It is exact-value redaction, not a guarantee that arbitrary output is free of sensitive information; transformed/encoded values and file-based credentials are not automatically discovered. Original imported evidence is intentionally preserved and is not run through log redaction.

### Predefined scans

Operators can use a fixed preset or run tools independently. Both Prowler/Kubescape paths share the same parsers and triage behavior. CloudOyabun does not install the scanners automatically; only the chosen scanner must be available on `PATH`. Standalone imports require no installed scanners or credentials.

| Tool | Fixed preset | Output handling |
| --- | --- | --- |
| Prowler | Selected provider, no check/service/status/region filters, OCSF JSON, verbose output | Import automatically; exit 0 and 3 are valid scan completion codes |
| Kubescape | `scan framework all`, selected context, JSON, verbose, `--keep-local` | Import automatically; exit 0 required for successful execution |
| AzureHound | `list` with the selected tenant, verbosity 1, explicit JSON output file | Collection only; preserve the file for BloodHound, never create CloudOyabun findings |

```sh
# AWS: native AWS credentials/profile, including AWS_PROFILE
.venv/bin/python -m cloudoyabun scan prowler --assessment ASSESSMENT_ID --provider aws

# Azure / Microsoft 365: existing Azure CLI login
.venv/bin/python -m cloudoyabun scan prowler --assessment ASSESSMENT_ID --provider azure
.venv/bin/python -m cloudoyabun scan prowler --assessment ASSESSMENT_ID --provider m365

# Azure / Microsoft 365: service principal environment instead
.venv/bin/python -m cloudoyabun scan prowler --assessment ASSESSMENT_ID --provider azure --auth env

# GCP: credentials configured as required by Prowler
.venv/bin/python -m cloudoyabun scan prowler --assessment ASSESSMENT_ID --provider gcp

# Kubernetes: explicitly select the cluster context
.venv/bin/python -m cloudoyabun scan prowler --assessment ASSESSMENT_ID --provider kubernetes --context lab
.venv/bin/python -m cloudoyabun scan kubescape --assessment ASSESSMENT_ID --context lab

# AzureHound: native configuration/environment; output goes to BloodHound
.venv/bin/python -m cloudoyabun scan azurehound --assessment ASSESSMENT_ID --tenant example.onmicrosoft.com
```

Prowler Azure/M365 `--auth env` uses `--sp-env-auth` and the tool's service-principal environment variables (typically `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID`). AzureHound supports its native configuration and `AZUREHOUND_*` variables, such as `AZUREHOUND_APP` plus `AZUREHOUND_SECRET`, or `AZUREHOUND_REFRESH_TOKEN`. Secrets are not accepted as CloudOyabun scan arguments. Tool-native permissions, authentication constraints, dependencies, and credential expiration still apply.

`--dry-run` prints the planned arguments without creating a run or contacting a target. Scans have a 7200-second default timeout, adjustable with `--timeout`; no automatic scan retries are enabled. The runner first executes a logged version probe. The tool's reported version is recorded, not claimed as a compatibility certification. Output is written to a new private directory beneath the database directory's `runs/` folder and retained for independent inspection or later import.

Prowler/Kubescape output is collected even on a nonzero exit or timeout when a file exists. Findings do not turn a failed execution into a successful one. Missing, malformed, or oversized results turn an otherwise successful scan into a failed run, with the reason logged. Artifacts have links back to source executions; importing identical bytes again preserves existing analyst decisions and adds the new execution association. Older files imported manually have no inferred execution history.

AzureHound's file is not parsed or stored in the findings/artifact database. The command returns its path, size, and SHA-256; the execution journal records these details. A failed or cancelled collection remains failed/cancelled even when a partial file exists. File validity and graph ingestion belong to BloodHound. AzureHound output has no import-size limit because CloudOyabun hashes it incrementally without decoding it.

“Full” means the tool's broad preset against the target accessible with the configured credentials. It does not guarantee complete coverage when permissions, provider APIs, optional host evidence, or other prerequisites are missing. Kubescape runs all its available built-in frameworks without namespace filters; this preset does not deploy a host sensor or separately enable container image vulnerability scans. Assessment scope is operator-provided context, not an enforced cloud-resource allowlist.

### Supported import shapes

The Prowler parser consumes JSON arrays in the shape emitted by [Prowler 5.10.0's OCSF output adapter](https://github.com/prowler-cloud/prowler/blob/5.10.0/prowler/lib/outputs/ocsf/ocsf.py). Field extraction was checked against that source; compatibility testing currently uses synthetic fixtures, not a live Prowler scan. ASFF, CSV, NDJSON, and legacy Prowler JSON are not supported yet.

Records must identify Prowler in `metadata.product.name` and include a string `finding_info.title`. Optional indexing fields remain unset when absent. `status_code` supplies the check result; OCSF `status` remains the native lifecycle state in the payload. All fields, including unknown nested fields, remain in the stored payload, and the original file bytes remain available for download. Only the first resource is indexed for the initial asset column; additional resources remain in native evidence.

Kubescape imports the native resource/control posture JSON format: each `results[].controls[]` record remains intact, with its resource ID and cluster indexed separately and its original JSON location recorded. Controls found only in `summaryDetails.controls` (for example skipped checks without resource results) are also retained. Severity labels are taken from native control/summary fields, never derived from score factors; older output without labels remains unspecified. Other report-level content, including coverage details and resource objects, remains in the original downloadable file.

The CLI defaults to format detection; use `import ... --tool prowler` or `--tool kubescape` for an explicit parser. The UI provides equivalent choices. AzureHound JSON is explicitly rejected with guidance to use BloodHound. Unknown or syntactically invalid data cannot be auto-detected; selecting the known format allows malformed files to be archived with a failed import diagnostic.

Imports are limited to 25 MiB. Duplicate detection uses assessment, file hash, adapter, and parser version. Identical files in different assessments remain separate. Rejected records retain their original artifact location and an import diagnostic. A partly valid array is marked `partial`; a malformed file or wholly rejected array is marked `failed`. An empty array imports successfully with zero findings and does not establish assessment coverage.

## Current boundaries and next work

- This is a single-analyst local preview. It has no user authentication or tenant authorization and must not be exposed as a shared network service. Local Host validation and mutation tokens protect the browser API from basic cross-site requests; they do not provide multi-user access control.
- Tool installation and native authentication are operator-managed. Prowler/Kubescape presets include version probes, execution, and automatic import; AzureHound includes collection only. Additional authentication modes and enforced cloud scope validation are not implemented. No actual cloud scans run as part of setup or the demo.
- Automatic recovery after abrupt worker termination (for example SIGKILL or host power loss) is pending. Already committed logs survive, but an unfinished run can remain marked `running`. Automatic log retention/rotation and database backup tooling are also pending.
- Imports are synchronous and parse the file in memory. SQLite stores original artifacts as BLOBs for transactional persistence. Large-assessment optimization, background import jobs, and external artifact storage are future work.
- Reports currently provide categories, order, notes, native records, and evidence references. Rich report templates, multiple export formats, and grouped report narratives are future work.
- Additional import adapters, asset relationships and dynamic tool-specific columns remain future work. Suppression, import comparisons, decision carry-forward and batched AI review are available; see the analyst guide.

## Integration verification references

CLI options and output structure were inspected against these upstream sources:

- [Prowler 5.10.0 CLI parser](https://github.com/prowler-cloud/prowler/blob/5.10.0/prowler/lib/cli/parser.py) and provider argument definitions.
- [Kubescape framework command](https://github.com/kubescape/kubescape/blob/80cd6203e880b7ad491df8336252d6b5ad670642/cmd/scan/framework.go) and [JSON report writer](https://github.com/kubescape/kubescape/blob/80cd6203e880b7ad491df8336252d6b5ad670642/core/pkg/resultshandling/printer/v2/jsonprinter.go).
- [AzureHound full collection command](https://github.com/SpecterOps/AzureHound/blob/b54bdfe4f0af6eff2d55cf7c6e3d6798c70d8167/cmd/list-root.go) and [native configuration](https://github.com/SpecterOps/AzureHound/blob/b54bdfe4f0af6eff2d55cf7c6e3d6798c70d8167/config/config.go).

Automated verification uses synthetic JSON fixtures and temporary local executable doubles. It does not establish live-cloud compatibility across all tool versions. The next integration validation step is a real authorized assessment with the installed tool versions and representative output files.

## Further guides

- [Analyst workflow, comparisons and suppression](analyst-guide.md)
- [AI configuration, native evidence and batching](ai.md)
- [Operations and troubleshooting](operations.md)
