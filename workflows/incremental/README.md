# Incremental build stages

The phishing pipeline was built and verified one stage at a time. Each stage is a complete, importable workflow that adds to the previous one. Use them to understand how the pipeline works, or to debug a single part in isolation.

| Stage | File | Adds |
|---|---|---|
| 1 | [`stage-1-trigger-and-ioc-extraction.json`](stage-1-trigger-and-ioc-extraction.json) | Gmail Trigger and **Extract IOCs** |
| 2 | [`stage-2-url-analysis.json`](stage-2-url-analysis.json) | URLScan and VirusTotal URL analysis, merged summary |
| 3 | [`stage-3-ai-analysis-and-report.json`](stage-3-ai-analysis-and-report.json) | Gemini analysis and the HTML report e-mail |
| 4 | [`stage-4-attachment-analysis.json`](stage-4-attachment-analysis.json) | SHA-256 lookups (VirusTotal, MalwareBazaar) for attachments |

## Stage 1 - trigger and IOC extraction

![Stage 1](../../assets/screenshots/20-stage1-canvas.png)

The Gmail Trigger polls every minute; **Extract IOCs** produces sender, subject, body, URLs and attachment metadata.

![Extract IOCs output](../../assets/screenshots/18-node-extract-iocs-output.png)

## Stage 2 - URL analysis

![Stage 2](../../assets/screenshots/21-stage2-canvas.png)

Each URL goes to URLScan and VirusTotal, the flow waits for the scans and merges both reports.

![URL results](../../assets/screenshots/19-node-url-results-output.png)

## Stage 3 - AI analysis and report

Adds *Build AI Request*, the Gemini call and *Build Report* / *Send Report* (see [prompts](../../prompts/phishing-analyst.md)).

## Stage 4 - attachment analysis

Adds attachment handling. The final result is the phishing pipeline in [`../phishing-analysis.json`](../phishing-analysis.json), which is also part of [`../ai-soc-copilot-full.json`](../ai-soc-copilot-full.json).

> Import the stage files only for learning; for real use import the full workflow.
> Remember to select your own credentials and replace `YOUR_EMAIL@gmail.com`.
