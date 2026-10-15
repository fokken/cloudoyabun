# Local operations

## Installation and running

Use Python 3.10+ and a virtual environment; install pinned dependencies from `requirements-dev.lock`. No Node build is needed. Scanner binaries are separate dependencies. Windows can import data, but execution currently requires POSIX.

The default database is `.cloudoyabun/cloudoyabun.sqlite3`. Override with `CLOUDOYABUN_DB` or `--db PATH` before a CLI subcommand. The synthetic demo uses `.cloudoyabun/demo.sqlite3` only when explicitly selected. Avoid comparing data in one database while serving another.

The browser server binds to `127.0.0.1:8787`. Use `serve --port 8788` if needed. This is a local single-analyst application; local session tokens and Host validation are not team authentication.

## Persistence and backup

Schema version 5 is initialized/migrated when a database opens, preserving existing findings. SQLite contains artifacts, findings, analyst audits, reports, AI snapshots, comparisons, suppression rules and workflow audits. Scan output lives beside the database under `runs/`; AzureHound output is retained there and is not stored as an imported artifact.

Before upgrading, stop the server and active CLI jobs, then back up the database and its adjacent `runs/` directory. If SQLite `-wal`/`-shm` files remain, preserve them alongside the database; do not copy only an actively written database file. Restore into a separate directory and verify it before replacing your working data. Automated backup/restore and retention tooling are not implemented.

Treat backups, exports and AI snapshots as sensitive assessment data. Database and newly collected output use restrictive file permissions. Tool-native output can contain secrets even though execution logs redact configured secret values.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Browser cannot connect | Correct port and running `serve` process |
| Old UI after upgrade | Restart server and reload browser |
| Missing local session token | Reload; token changes on server restart |
| Scan version check failed | Binary on `PATH`, executable permissions, execution logs |
| Import rejected | Supported JSON format and 25 MiB file limit; use explicit parser for malformed known output |
| Fewer findings visible | Search/filter settings, suppressed visibility, collapsed groups |
| AI send disabled | Model, endpoint/protocol and required credentials; restart and prepare new preview |
| AI request failed | Model access, network, JSON output support, context size; inspect completed batches and logs |
| Carry-forward conflict | Source/target changed; create a new comparison |
| Run remains running after crash | Abrupt-termination recovery is pending; inspect logs before starting fresh work |

## Checks for a deployment

Run `.venv/bin/python -m pytest -q` and optionally `node --check cloudoyabun/static/app.js`. Tests do not contact clouds or real model servers. Validate representative real exports and an authorized scan in your environment, then test your chosen AI deployment with appropriate data.

Current limits: 25 MiB synchronous imports; SQLite BLOB artifact storage; no durable job queue, crash recovery, multi-user authentication, automatic retention or rich document export. Review [AI limits](ai.md) separately for model workloads.
