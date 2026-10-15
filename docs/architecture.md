# Architecture & node reference

Both pipelines live in `workflows/ai-soc-copilot-full.json`; each is also available as a standalone file.

## Design principles

1. **Enrich first, then ask the model.** The LLM receives facts (scan results, reputation scores) rather than guessing from raw text.
2. **Structured output.** Gemini is called with `responseMimeType: application/json` and a response schema, so downstream code parses fields, not prose.
3. **Untrusted input.** E-mail bodies, file names and tool output are declared untrusted data in the system prompt.
4. **Deterministic guard rails.** Threat-intel signals can raise (or, for EICAR, cap) the verdict regardless of the model's answer.
5. **Fail safe.** Errors on enrichment calls continue the flow (`onError: continueRegularOutput`) with retries; a failed AI call produces a "manual review required" report instead of silence.
6. **Minimal data exposure.** Attachments are hashed locally; only hashes leave the machine.

## Pipeline 1 - Phishing & Attachment Analysis

| Node | Type | Purpose |
|---|---|---|
| Gmail Trigger | Gmail Trigger | Polls every minute, downloads attachments, ignores the copilot's own reports (`-subject:"SOC AI ALERT"`). |
| Extract IOCs | Code | Extracts sender, subject, body, URLs (max 3) and attachment metadata (max 5). Uses a regex host helper because `new URL()` is unavailable in the Code node sandbox. |
| Has URLs? | IF | Routes to URL analysis or to *No URLs*. |
| Split URLs | Code | One item per URL. |
| URLScan Submit / Wait URLScan / URLScan Report | HTTP, Wait, HTTP | Submit (`unlisted`), wait 30 s, fetch the result. |
| VirusTotal Submit / Wait VirusTotal / VirusTotal Report | HTTP, Wait, HTTP | Submit URL, wait 15 s, fetch the analysis. |
| Merge URL Reports | Merge | Combines both reports per URL. |
| Summarize URL Results | Code | One compact record per URL (detections, verdicts, final host). |
| No URLs | Code | Empty URL result so the flow continues. |
| Prepare Attachments / Has Attachments? | Code, IF | Lists attachments; routes to hashing or to *No Attachments*. |
| Compute SHA256 | Code | SHA-256 of each file (pure-JS fallback if `crypto` is unavailable). |
| VirusTotal File Lookup | HTTP | `GET /files/{sha256}`. |
| MalwareBazaar Lookup | HTTP | `query=get_info` hash lookup. |
| Summarize Attachment Results | Code | Per-file verdict: detections, MalwareBazaar hit; unknown = *unverified, not proof of safety*. |
| No Attachments | Code | Empty attachment result. |
| Build AI Request | Code | Builds the Gemini request body (system prompt, schema, data) and keeps the original context. |
| Gemini Phishing Analysis | HTTP | `gemini-3.5-flash-lite` `generateContent`. |
| Build Report | Code | Parses the verdict, escapes HTML, defangs IOCs, renders the report. |
| Send Report | Gmail | Sends `[RISK] SOC AI ALERT - classification` to the analyst. |

## Pipeline 2 - Wazuh Alert Triage

| Node | Type | Purpose |
|---|---|---|
| Wazuh Webhook | Webhook | `POST /webhook/wazuh-alert`. |
| Normalize Alert | Code | Flattens the alert (rule, level, MITRE, agent, IP, user, hashes, URLs) and computes the de-dup key. |
| New Alert? | IF | Drops repeats (workflow static data; production executions only). |
| Has URL? | IF | URL enrichment branch. |
| WZ URLScan Submit / Wait / Report | HTTP, Wait, HTTP | URLScan verdict. |
| WZ VT URL Submit / Wait / Report | HTTP, Wait, HTTP | VirusTotal URL analysis. |
| Has IP? | IF | IP enrichment branch. |
| WZ VT IP / WZ AbuseIPDB | HTTP | IP reputation and abuse confidence score. |
| Has Hash? | IF | Hash enrichment branch. |
| WZ VT Hash / WZ MalwareBazaar | HTTP | File reputation. |
| Build WZ Context | Code | Collects all enrichment into a `signals` object. |
| Build WZ AI Request | Code | Builds the Gemini request. |
| WZ Gemini Triage | HTTP | Structured triage verdict. |
| Build WZ Report | Code | Applies guard rails, renders the report. |
| True Positive? | IF | True Positive -> e-mail; otherwise logged only. |
| WZ Send Report | Gmail | Sends the report. |
| WZ Log False Positive | Set | Records the false-positive decision. |

## Timing & rate limits

| Step | Setting |
|---|---|
| URLScan wait | 30 s |
| VirusTotal wait | 15 s |
| HTTP retries | 3 attempts, 5-15 s between tries |
| Gmail polling | every minute |
| Limits per e-mail | 3 URLs, 5 attachments |

The VirusTotal public API allows 4 requests per minute, which is the main throughput constraint of the lab setup.

## Guard rails (Wazuh)

| Condition | Outcome |
|---|---|
| EICAR test file | True Positive, capped at Medium, labelled test artefact |
| VT detections >= 10, or MalwareBazaar hit with >= 5 detections | Critical |
| VT detections >= 5, AbuseIPDB >= 75, or any MalwareBazaar hit | at least High |
| URLScan verdict malicious | counts as 5 detections |
| AI error / invalid JSON | True Positive, Medium, manual review required |

See [`../prompts`](../prompts) for the exact prompts and schemas.
