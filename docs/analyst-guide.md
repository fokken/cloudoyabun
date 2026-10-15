# Analyst guide

## 1. Create an assessment and collect evidence

Create a workspace with a name and authorized scope. Scope describes the engagement; it is not an enforced scanner boundary. Execute a CLI preset or import output collected independently. The import selector detects Prowler OCSF and Kubescape posture JSON; select an explicit format if needed.

Original bytes and SHA-256 are preserved. Reimporting identical bytes with the same parser in the same assessment reuses the original import. A new export with different bytes is a separate import. AzureHound is collection-only; take its output to BloodHound.

## 2. Investigate and triage

Group by check to browse repeated checks together; expand a group for individual records. Group provider and severity remain visible. Conflicting severity values display as Mixed. Severity columns and filters use the effective value: the analyst override when set, otherwise the original tool severity. Each row identifies Tool or Analyst override; groups show override counts and Mixed when effective values differ. Labels sort alphabetically. Finding details always show Original tool severity and Effective severity separately. Set an analyst override individually or in bulk; Use tool severity removes it. Overrides are audited and reports include both effective and original severity.

Open a finding for native JSON, source artifact, metadata provenance, analyst notes and decision history. Set disposition, priority, category, tags, report order and report inclusion independently. Native status and analyst disposition are different: a tool's failed check is not automatically a confirmed report issue.

Select individual records across pages to add/remove tags or set disposition, category and report inclusion in bulk. Choose a disposition, **Set category** (and enter a value), or **Clear category**, or choose **Add to report** / **Remove from report**, then **Apply decisions**. This changes inclusion for the next report snapshot; existing snapshots remain unchanged. Keep options preserve existing values; these fields can be updated together. Bulk analyst notes support **Append notes**, **Replace notes**, and **Clear notes**. Append keeps existing text and separates the added text with a blank line; Keep notes leaves it unchanged. The 20,000-character limit is checked for every finding before the transaction commits. Changes are atomic: if any selected finding changed since selection, none are updated. Each changed finding gets a decision-history entry. Changing filters clears selection. The current checkbox selection is limited to 1,000 records; larger AI scopes can be prepared from the AI page.

## 3. Use AI assistance

Configure a server using [AI setup](ai.md). Select findings and choose **Analyze with AI**, or open **AI assistance** and preview the whole assessment or an exact category. On the AI page, choose native evidence inclusion and batch size before preparing a preview (these settings also apply to subsequent selected-finding previews).

Inspect the exact input, destination, model and batch count. **Send to AI server** is the only action that starts provider requests. Category scope uses analyst-assigned category values, not an inferred taxonomy. Whole-assessment analysis includes all imported records, including suppressed findings and records from older imports. It does not silently choose the latest scan. Use explicit selection to narrow that scope.

The final analysis contains area summaries, suggested priorities, rationale, next steps and clickable finding references. Completed batch analyses remain inspectable, including when a later request fails. Mark results reviewed or dismissed. These labels do not edit findings, suppress results or put AI prose into a report. If you use a suggestion, verify its evidence and enter your own analyst notes.

## 4. Suppress recurring noise

Open a finding and expand **Suppress recurring noise**. Enter a reason, optionally a future UTC expiry, and choose whether to match only this resource or all resources for this check in the same environment.

Rules match exact tool, provider, environment, check ID and native status; resource matching is optional. Complete resource identity is required to create a rule. Rules apply to existing and future imports across assessments with the same environment identity. They never change source evidence or analyst disposition.

The workbench defaults to **Hide suppressed**. Choose **Suppressed only** to inspect hidden records or **Show all** to see everything. Overall statistics still count all records. Manage rules in **Repeat assessments**; disabling a rule restores visibility. Expiry also stops matching. Suppression does not remove a previously selected finding from reports: review report inclusion separately.

## 5. Compare scans and carry decisions forward

In **Repeat assessments**, select an earlier and later imported artifact. These may belong to different assessments but must use the same parser format. The dropdown shows import status; partial or failed imports need extra scrutiny.

Matches use exact tool, provider, environment, resource and check ID. Missing identity or duplicate candidates are **ambiguous** and never carried automatically. The comparison shows:

| State | Meaning |
| --- | --- |
| New | Identity appears only in the later import |
| Not observed | Identity appears only in the earlier import; this is not proof of remediation |
| Changed | Matching identity, different native status or severity |
| Unchanged | Matching identity, same native status and severity; other evidence may differ |
| Ambiguous | Missing identity or more than one candidate |

Expand rows to inspect earlier/later records and analyst decisions. **Carry forward eligible decisions** copies category, tags, disposition, priority, severity override and notes from edited source findings to untouched later findings classified unchanged. It does not copy report selection/order, overwrite target decisions or modify changed/ambiguous matches. The whole operation fails if eligible source or target revisions changed since preview; compare again. Each copied decision records the source finding ID in its audit history. A comparison can be applied once.

## 6. Build a report

Select relevant findings for reporting, assign categories and report order, and write analyst notes. In **Reports**, create a Markdown snapshot. A snapshot freezes the selected content and references; later imports and triage do not alter it.

The current report lists individual findings. Combined issue narratives and DOCX/PDF exports are not yet implemented.
