# AI configuration and evidence handling

## Connect a server

AI is disabled until an endpoint and model are explicitly configured. There is no default provider URL and no automatic fallback to a hosted provider. Configure environment variables before starting CloudOyabun; restart to apply changes.

```sh
export CLOUDOYABUN_AI_BASE_URL=http://127.0.0.1:11434/v1
export CLOUDOYABUN_AI_MODEL=your-installed-model
export CLOUDOYABUN_AI_PROTOCOL=chat
.venv/bin/python -m cloudoyabun serve
```

| Variable | Meaning |
| --- | --- |
| `CLOUDOYABUN_AI_BASE_URL` | API base URL including `/v1` where needed; no default; required explicitly |
| `CLOUDOYABUN_AI_MODEL` | Required model identifier installed/available at that server |
| `CLOUDOYABUN_AI_PROTOCOL` | `chat` (default) or `responses` |
| `OPENAI_API_KEY` | Optional for custom servers; required for the official OpenAI endpoint; sent as a Bearer token if present |

Do not append `/chat/completions` or `/responses` to the base URL. `chat` requires JSON-object response support; `responses` uses strict JSON-schema output. Both are validated locally. Model installation is operator-managed. Use trusted local networks for HTTP and HTTPS for remote servers. Redirects are rejected.

For OpenAI, set the base URL to `https://api.openai.com/v1`, select `responses`, and configure an available model and API key. The transport follows [official structured-output documentation](https://developers.openai.com/api/docs/guides/structured-outputs). Custom servers differ in supported parameters and context sizes; validate your model/server combination.

## Preview and data scope

No AI request runs on startup or during preview. A preview freezes endpoint, protocol, model and input; configuration or prompt-version changes require a new preview. Invalid URLs or ports leave AI disabled. Metadata includes IDs/revisions, tool, title, provider, native severity/status, a separately labeled analyst severity override, check ID, service and category.

Optional native evidence adds the original finding payload, artifact/record locator and resource/environment identifiers. Structured fields whose names indicate credentials, secrets, tokens or private/API/access keys are redacted recursively. Known environment-secret values and common labeled token patterns are also removed from strings. Redaction is best-effort: arbitrary free text, identifiers or secrets under unexpected field names can remain. Inspect the preview before sending. Analyst notes, tags and assessment scope are excluded.

Native JSON above 12 KB is replaced with an explicitly marked excerpt. Excessive nesting is marked omitted. Evidence stays unchanged in its original artifact; redaction only affects the AI snapshot.

## Batching and summaries

Prepare 1–2,000 findings, at most 8 MB total. Inputs are ordered by provider, check, environment and resource; batches are bounded by the chosen 1–100 findings and 100 KB. Choose smaller batches for local models. Byte limits are not token estimates; the selected model must still fit the prompt, schema and output.

Each batch produces area summaries with source IDs. Citation IDs must belong to that batch. Completed results are redacted as structured text values and saved before the next request; source citation IDs are preserved. Multiple batches are combined hierarchically in bounded groups; synthesis citations must refer to findings cited by its input summaries. Every batch enters synthesis, but a summary may omit individual findings; it is not a coverage ledger. Inspect retained batch results for detail.

The model receives untrusted evidence with instructions to ignore embedded commands. No tools are provided. It cannot execute scanners, suppress records or write analyst decisions. Valid IDs establish traceability, not correctness; an analyst must verify that the cited evidence supports the claim.

## Execution and failure behavior

Each request has a 90-second socket timeout, 6,000 output-token limit and 1 MiB response limit. Multi-batch jobs take longer overall and run in the web server's thread pool. There are no automatic retries. Logs record batch progress, synthesis, completion and generic failures without credentials/provider error bodies. Completed batch results survive later failures; a failed overall analysis has no final summary. Prepare a fresh preview to retry.

History retains input, model/endpoint/protocol, prompt version, successful final result, batch results, available token counts and review status/timestamp. The UI lists the latest 100 analyses per assessment. Request usage totals are stored on successful completion; failed jobs can still incur provider charges. Responses calls use `store:false`; provider retention and billing rules still apply.

Durable background workers, cancellation/resume, automatic interrupted-job recovery and model-quality evaluation are not implemented. No live model compatibility or quality claim is implied by the mocked-provider test suite.
