<p align="center"><img src="cloudoyabun/static/logo.svg" alt="CloudOyabun assessment workbench" width="680"></p>

# CloudOyabun

A local workbench for cloud and Kubernetes security assessments. Run broad tool presets or import existing results, investigate native evidence, triage findings, and build a technical report. Tool output remains intact; sortable metadata and analyst decisions live alongside it.

## Start here

Requires Python 3.10+; tool execution requires Linux or macOS.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.lock
.venv/bin/python -m cloudoyabun init
.venv/bin/python -m cloudoyabun serve
```

Open [CloudOyabun](http://127.0.0.1:8787/). Create an assessment, then import Prowler OCSF or Kubescape JSON. The app is a single-analyst, loopback-only service; do not expose it as a shared network service.

For a separate synthetic demo, stop the existing server, then run:

```sh
.venv/bin/python -m cloudoyabun --db .cloudoyabun/demo.sqlite3 demo
.venv/bin/python -m cloudoyabun --db .cloudoyabun/demo.sqlite3 serve
```

Each `demo` invocation creates a new assessment with six synthetic findings. No cloud account is contacted.

## Supported integrations

| Tool | Automated CLI execution | Standalone import |
| --- | --- | --- |
| Prowler | Broad provider scan; automatic import | JSON OCSF arrays (`.ocsf.json`) |
| Kubescape | All built-in frameworks; automatic import | Native posture JSON |
| AzureHound | Full collection, output retained for BloodHound | None: BloodHound owns parsing and graph analysis |

Install scanners separately on `PATH` and configure their native credentials. Imports do not require scanner installation. CloudFox, ROADtx, Nmap and BBOT adapters are not implemented.

```sh
.venv/bin/python -m cloudoyabun scan prowler --assessment ASSESSMENT_ID --provider aws
.venv/bin/python -m cloudoyabun scan kubescape --assessment ASSESSMENT_ID --context my-cluster
.venv/bin/python -m cloudoyabun scan azurehound --assessment ASSESSMENT_ID --tenant example.onmicrosoft.com
.venv/bin/python -m cloudoyabun import ASSESSMENT_ID /path/to/results.json
```

Add `--dry-run` to inspect a scan command without executing it. To use a nondefault database, put `--db PATH` before the subcommand.

## What you can do

- Browse expandable check groups with provider and clearly labeled tool/analyst severity; filter, search and bulk-edit tags, category, disposition, notes and report inclusion.
- Preserve original artifacts, individual native payloads, provenance and analyst decision history.
- Inspect granular execution events, stdout/stderr, failures and import diagnostics.
- Preview optional AI input, analyze selections or entire categories in batches, and review evidence-linked summaries and priorities. Custom/local OpenAI-compatible servers are supported; no provider endpoint is configured by default.
- Compare two imports, explicitly carry forward eligible analyst decisions, and manage reusable suppression rules.
- Freeze selected findings in categorized, ordered Markdown report snapshots.

## Guides

- [Analyst guide](docs/analyst-guide.md): findings, AI review, suppression, comparisons and reporting.
- [AI setup and data handling](docs/ai.md): endpoints, models, batching, redaction and limitations.
- [Operations](docs/operations.md): installation, databases, backups and troubleshooting.
- [CLI and integration reference](docs/development.md): commands, credentials and supported formats.
- [Architecture](docs/architecture.md): modules, persistence and design boundaries.
- [Review notes](docs/review.md): recent fixes, verification, and remaining priorities.

## Verification and limits

```sh
.venv/bin/python -m pytest -q
node --check cloudoyabun/static/app.js
```

Tests use synthetic scanner output, local executable doubles and mocked AI responses. They do not establish compatibility with every scanner/model version or verify real-cloud results. Rich report narratives and DOCX/PDF exports, team authentication, durable background jobs and crash recovery remain future work.
