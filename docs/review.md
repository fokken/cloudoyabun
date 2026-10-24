# Fix verification — 2026-10-24

Implemented the five issues from the October 20 source review:

- Archive restore validates command/event JSON, analyst-history structure, scalar types, Unicode, integer ranges and v2 source IDs before database writes. Invalid archives leave no partial assessment. Version 1 remains supported.
- Version 2 archives preserve original assessment, artifact, run and finding IDs. Restore logs an ID mapping and archive checksum without rewriting historical event content; repeated exports preserve the mapping chain. Export reads a consistent database snapshot and refuses active source runs.
- Import failures receive a terminal status. Invalid Unicode records are diagnosed individually. Explicit retry is available through the CLI and API/UI for empty failed/interrupted imports, preserving evidence and logs. CLI recovery of stale running imports requires an operator confirmation flag and refuses live recorded workers; automatic crash recovery remains future work.
- A finding save captures its finding and assessment context. Delayed successes and failures cannot close or overwrite feedback in a different dialog, or clear another finding's selection.
- CLI report exports use private temporary files and atomic replacement, retaining mode 0600 for both new and replacement files.

Regression coverage includes malformed archives with no database writes, v1 compatibility and repeated restore provenance, Unicode diagnostics, injected database failures and retries, live-worker recovery refusal, report permissions, and JavaScript tests for delayed save responses. The full Python suite passed (151 cases at that run), and all four JavaScript save-race checks passed. Targeted validation was rerun after final range checks. All tests use synthetic data; no cloud scans or model requests are needed.

---

# Project review — 2026-10-15

Reviewed application services, API/CLI boundaries, scanner adapters, execution logging, persistence, AI handling, repeat-assessment matching, browser workflows, packaging and documentation. This is a source review and regression pass, not a penetration test or live scanner/model compatibility certification.

## Changes made

- AI-result redaction now operates on text values before JSON serialization. Redacting serialized JSON could consume quote/delimiter characters and fail an otherwise valid analysis. Completed batch results now receive the same redaction before storage and synthesis; citation IDs remain intact.
- Malformed endpoint hosts, invalid ports and whitespace are rejected as configuration errors instead of breaking the configuration screen or enabling an unusable endpoint. No default endpoint or hosted-provider fallback was introduced.
- Previews with a different prompt version cannot be submitted using new instructions while retaining old version metadata.
- AI metadata previews select only needed columns; native previews iterate through findings and enforce the aggregate input bound as they go. Scan comparisons avoid loading artifact BLOBs and native finding payloads that are not compared.
- The generic execution runner now rejects NaN and infinite timeouts before creating a run. Scanner presets already rejected these values.
- Excessively nested JSON during format detection returns a validation error instead of an uncaught recursion exception.
- Late finding-detail requests cannot replace a newer selection or reopen a finding from a previous assessment. AI completion does not replace the current view after navigation; stale provider previews have a disabled send button.
- Pydantic 2 is declared directly in package dependencies, matching the validation APIs used by the application.
- The README uses a repository-local SVG rendition of the existing 雲 / cloudoyabun branding and describes current bulk editing/severity features.

## Verification

122 tests pass, including added regressions for malformed endpoints, quoted secret redaction, saved batch redaction, prompt-version mismatch, non-finite timeouts and deeply nested JSON. JavaScript syntax, Python compilation and Git whitespace checks also pass. The test suite still emits one upstream Starlette/httpx deprecation warning.

Tests use synthetic scanner fixtures and mocked AI responses. No cloud scan or real model request was made for this review.

## Remaining priorities

1. Validate representative real Prowler/Kubescape exports, AzureHound collection and the intended local model server.
2. Add durable job execution, interrupted-run recovery and AI cancellation/resume before relying on unattended long-running jobs.
3. Extend reporting with grouped issue narratives and document exports.
4. Add automated backup/restore and retention tooling; large imports still use synchronous parsing and SQLite artifact BLOBs.
5. Add authentication and tenant isolation if the application moves beyond a loopback-only analyst workstation.

Best-effort redaction does not establish that evidence is safe to disclose. Analyst input preview and explicit endpoint configuration remain required parts of the AI workflow.
