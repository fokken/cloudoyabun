# Architecture

CloudOyabun is a modular local application using Python, FastAPI, SQLite and bundled browser JavaScript/CSS. CLI and HTTP routes call application services. There is no separate durable worker service.

## Module boundaries

| Module | Responsibility |
| --- | --- |
| `db.py` | Schema migration, SQLite connections and record decoding |
| `archive.py` | Versioned scan archives, validation, transactional restore and original-ID mappings |
| `service.py` | Assessments, native imports, findings, analyst triage, audit and report snapshots |
| `integrations/` | Tool-specific parsing and source-field metadata extraction |
| `scans.py` | Validated broad presets, version probes and output discovery |
| `execution.py`, `events.py` | POSIX execution, redacted streams, timeout/cancellation and durable event journal |
| `ai.py` | Configured provider transport, input snapshots, redaction, batch analysis, synthesis and citation validation |
| `reassessment.py` | Exact-identity comparisons, atomic decision carry-forward and reversible suppression |
| `api.py`, `cli.py`, `static/` | Local HTTP/CLI interfaces and analyst workbench |

## Evidence flow

CLI collection or independent export → original artifact → native records with sortable metadata → analyst investigation and decisions → frozen report snapshot.

Prowler and Kubescape support execution plus import. AzureHound is deliberately collection-only: preserve the file for BloodHound to ingest and analyze. Its records do not enter the finding database.

Findings retain their tool payload, artifact locator and metadata provenance. Analyst fields are separate from native severity/status and evidence. Import identity is assessment + file hash + parser + parser version. Identical reimports preserve decisions; changed exports are separate artifacts.

## Storage and consistency

SQLite schema version 5 stores assessments, runs, events, artifacts, findings, analyst audit, reports, artifact/execution links, AI analyses, suppression rules, comparisons and workflow audit. Original imported artifacts are BLOBs; scanner output files are also retained on disk. AI schema additions use additive migration to preserve previous analyses.

Triage uses optimistic revision checks. Bulk tagging and decision carry-forward use transactions. Report snapshots freeze content. AI previews freeze input and provider configuration; generated suggestions never silently edit analyst fields.

## Repeat-assessment semantics

Identity is the exact tuple tool/provider/environment/asset/check ID. Missing identity or duplicates are ambiguous. Comparisons distinguish new, not-observed, changed native status/severity and unchanged native status/severity. Absence is not remediation and metadata agreement is not full evidence equality.

Carry-forward only targets untouched, unambiguous matches with agreeing native status/severity. It checks source/target revisions at application time and records source finding IDs in decision audit. Report inclusion and order are not copied.

Suppression is a reversible query-time visibility rule, not deletion or triage mutation. Rules match tool/provider/environment/check/native-status, optionally resource, and may expire. They span assessments within that exact environment scope. Browser defaults hide matches; CLI/API callers opt into suppression filtering. Reports and AI scopes do not silently exclude suppressed evidence.

## AI trust boundaries

No endpoint is configured by default and there is no hosted-provider fallback. Only explicit send starts a provider request. Server environment chooses endpoint, protocol and model; preview records them. Optional native evidence is redacted and bounded without changing stored source artifacts. Prompt instructions classify all evidence as untrusted; the model has no tools.

Batch requests validate citations against their supplied findings. Synthesis validates citations against input batch summaries. Completed batches are persisted incrementally. These checks prevent foreign finding IDs, not unsupported reasoning using valid IDs: analyst verification is still necessary.

Provider transport supports chat-completions JSON output or Responses structured output. No provider-specific SDK is required. Configuration and detailed limits are in [AI setup](ai.md).

## Execution and operational boundaries

Execution logs preserve incremental stdout/stderr and lifecycle events, including failures and collection/import diagnostics. Secrets from configured environment values are redacted; this is not a guarantee that arbitrary native output contains no sensitive information.

HTTP requests use thread-pool work for synchronous application operations. Long AI jobs run there too; there is no durable queue or resume. Committed events/results survive a crash, but an interrupted run may remain marked running. Imports are synchronous and memory-bounded. The server binds to loopback with Host checks and local mutation tokens, not multi-user authorization.

## Future work

- Real scanner/server compatibility fixtures and model-quality evaluation.
- Durable workers, cancellation/resume/recovery for AI, large imports and retention controls.
- Grouped report narratives and rich document exports.
- Asset relationships, more tool adapters and configurable native columns.
- Team authentication and deployment isolation if shared use is required.

For actual operator behavior, see the [analyst guide](analyst-guide.md), [CLI reference](development.md) and [operations guide](operations.md).
