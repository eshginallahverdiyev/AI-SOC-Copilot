# Troubleshooting

Problems below were all encountered while building the project.

| Symptom | Cause | Fix |
|---|---|---|
| Gemini node: **503** "model is overloaded / high demand" | Temporary load on the model | The node retries 3 times; re-run later. Switch to another Flash-class model if it persists. |
| Gemini node: **404** "model is no longer available" | Google retired or renamed the model, or it is not offered to new accounts | Change the model name in the URL of *Gemini Phishing Analysis* and *WZ Gemini Triage*. The workflow uses `gemini-3.5-flash-lite`. |
| Gemini returns an authentication / quota error | Missing key or free-tier quota exhausted | Check the *Google Gemini(PaLM) API* credential in both Gemini nodes. |
| Code node: `URL is not defined` / `new URL()` fails | The n8n Code-node sandbox has no `URL` class | Already handled: the workflow uses a regex host helper. Keep that approach in custom code. |
| The workflow keeps sending reports and triggering itself | The report lands in the watched mailbox | The Gmail Trigger filter `-subject:"SOC AI ALERT"` prevents this; keep the subject prefix if you edit it. |
| Webhook returns 404 for Wazuh | Using the **test** URL, or the workflow is not active | Publish the workflow and use `/webhook/wazuh-alert`. |
| Webhook works with `curl` but not from Wazuh | VM cannot reach the host / firewall | Use the host's address on the VM network, allow TCP 5678, check `/var/ossec/logs/integrations.log`. |
| Integration does nothing after editing `ossec.conf` | Manager not restarted or invalid XML | `sudo systemctl restart wazuh-manager`; check `/var/ossec/logs/ossec.log`. |
| A repeated alert is ignored | De-duplication | Intended. It only works in production executions; manual test runs are not de-duplicated. |
| Gmail node fails after about a week | Google OAuth app in *Testing* status: refresh token expires after 7 days | Re-authorise the credential, or publish the OAuth app. |
| VirusTotal 429 | Free API limit (4 requests/min) | The nodes retry; reduce alert volume (`<level>`, `<rule_id>`) or use a higher quota. |
| Import shows nodes with red credential warnings | Exports never contain credentials | Open each node and select your own credential. |
| Report says "unverified" for an attachment | The hash is unknown to VirusTotal / MalwareBazaar | Expected: *unknown is not proof of safety*. |
| MalwareBazaar returns 401 | Missing `Auth-Key` | Create the Header Auth credential with name `Auth-Key`. |
| URLScan submission fails for a URL | Blocked or invalid target, or quota | The branch continues with an error marker; the report states that the scan was unavailable. |

## Useful checks

```bash
docker compose logs --tail 100 n8n                 # n8n logs
sudo tail -f /var/ossec/logs/integrations.log      # Wazuh integration log
curl -i -X POST http://localhost:5678/webhook/wazuh-alert \
  -H 'Content-Type: application/json' \
  --data-binary @samples/wazuh/new-user-created.json
```
