# Testing the pipelines

## Wazuh pipeline: replay sample alerts

Publish the workflow, then send any file from [`samples/wazuh`](../samples/wazuh):

```bash
./scripts/send-sample-alert.sh samples/wazuh/ssh-bruteforce-malicious-ip.json
```

```powershell
.\scripts\send-sample-alert.ps1 -File samples\wazuh\ssh-bruteforce-malicious-ip.json
```

| Sample | Rule | What it exercises | Expected result |
|---|---|---|---|
| `eicar-file-added.json` | 87105 | File hash lookup (VirusTotal + MalwareBazaar) | True Positive, capped at **Medium** (EICAR test file) |
| `ssh-bruteforce-malicious-ip.json` | 100100, level 12 | IP reputation (VirusTotal + AbuseIPDB) | **Critical/High** if the IP has abuse reports |
| `new-user-created.json` | 5902 | No IOC: judged on rule, MITRE and log line | Medium/High, local user "hacker" |
| `ransomware-c2-connection.json` | 100100, level 15 | Destination IP reputation | **Critical** when TI agrees |
| `suspicious-download-url.json` | 100110 | URL branch (URLScan + VirusTotal) | Depends on current URL reputation |

Threat-intelligence results change over time (reputation of public IPs and URLs moves), so the exact severity can differ between runs; the guard rails guarantee that strong signals are never under-rated.

Sending the same alert twice within the de-duplication window is **suppressed** by design (production executions only).

![Reports](../assets/screenshots/08-report-wazuh-critical-bruteforce.png)

## Wazuh pipeline: real alerts with Atomic Red Team

On the monitored endpoint install `atomic-operator` and run a technique, for example a Linux shell technique (T1059.004):

![Atomic install](../assets/screenshots/14-terminal-atomic-install.png)
![Atomic run](../assets/screenshots/15-terminal-atomic-run.png)

The resulting alerts appear in the Wazuh dashboard:

![Discover](../assets/screenshots/11-wazuh-discover-alerts.png)

Only alerts at or above the integration `<level>` are forwarded to n8n.

## Phishing pipeline: sample e-mails

Send one of the files in [`samples/emails`](../samples/emails) to the mailbox connected to the Gmail Trigger (paste the text into a new message). Within a minute the report arrives.

| Sample | Exercises |
|---|---|
| `01-credential-phish.txt` | URL branch; no attachments |
| `02-hr-salary-attachment.txt` | Attachment branch (attach any file, e.g. the harmless EICAR test file) |
| `03-benign-newsletter.txt` | Control: expect low risk |
| `04-plain-no-urls.txt` | Neither branch; AI judges text only |

Report examples: [critical](../assets/screenshots/04-report-phishing-critical.png), [attachment](../assets/screenshots/05-report-phishing-high-attachment.png), [URL](../assets/screenshots/06-report-phishing-high-url.png).

> Use only harmless test material. Never attach or send real malware.

## Optional offline tests

`npm run check` runs workflow validation, the secret scan, the prompt-documentation check and a mock test suite that executes the Code nodes outside n8n with fixed inputs. It needs only Node 18+ and no API keys. These are developer tooling (used by CI) and are not required to run the workflow.

## Debugging in n8n

Open **Executions**, select a run and click a node to see its input and output. Use the *Test URL* only for the editor's "Listen for test event" mode.
