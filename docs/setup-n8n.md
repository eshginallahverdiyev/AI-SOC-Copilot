# Setting up n8n

## Requirements

- Docker Desktop (Windows 11 with WSL 2) or Docker Engine
- About 1 GB of RAM for the n8n container
- Accounts / API keys: VirusTotal, URLScan, AbuseIPDB, abuse.ch (MalwareBazaar), Google AI Studio (Gemini), a Google Cloud project for the Gmail OAuth client

The workflow was built and verified on n8n 2.42.x.

## 1. Start n8n

```bash
cp .env.example .env
docker compose up -d
docker compose logs -f n8n
```

![n8n running in Docker](../assets/screenshots/12-terminal-n8n-docker.png)

Open <http://localhost:5678> and create the owner account. To restart after changing settings: `docker compose restart n8n`.

## 2. Credentials

Create the credentials in **Credentials -> Create credential** (or from inside a node).

![Credentials](../assets/screenshots/16-n8n-credentials.png)

| Credential | Type | Where to get the key |
|---|---|---|
| VirusTotal | *VirusTotal API* | virustotal.com -> profile -> API key |
| URLScan | *urlscan.io API* | urlscan.io -> profile -> API keys |
| AbuseIPDB | *Header Auth*, name `Key` | abuseipdb.com -> API |
| MalwareBazaar | *Header Auth*, name `Auth-Key` | auth.abuse.ch -> Auth-Key |
| Gemini | *Google Gemini(PaLM) API* | aistudio.google.com -> API key |
| Gmail | *Gmail OAuth2 API* | see below |

### Gmail OAuth2

1. In Google Cloud Console create a project and enable the **Gmail API**.
2. Configure the OAuth consent screen and add your own address as a test user.
3. Create an **OAuth client ID** of type *Web application* and add n8n's **OAuth redirect URL** (shown in the n8n credential form, normally `http://localhost:5678/rest/oauth2-credential/callback`).
4. Paste the client ID and secret into the n8n credential and click **Sign in with Google**.

![Google OAuth client](../assets/screenshots/17-google-oauth-client.png)

> In *Testing* status Google expires refresh tokens after 7 days. Re-authorise, or publish the app.

## 3. Import and configure the workflow

1. **Workflows -> Import from file** -> `workflows/ai-soc-copilot-full.json`.
2. In **Send Report** and **WZ Send Report**, replace `YOUR_EMAIL@gmail.com` with your address.
3. Open every HTTP Request and Gmail node and pick the matching credential (imports never carry credentials).
4. Save and **Publish** the workflow. The production webhook (`/webhook/wazuh-alert`) and the Gmail trigger only run when the workflow is active.

![Full workflow](../assets/screenshots/01-n8n-full-workflow.png)

## 4. Choosing the Gemini model

The model is part of the HTTP Request URL in *Gemini Phishing Analysis* and *WZ Gemini Triage* (default `gemini-3.5-flash-lite`). Google retires and renames models; if you get a 404, change the model name in both nodes. See [troubleshooting](troubleshooting.md).

## 5. Reaching n8n from a Wazuh VM

Wazuh must be able to reach the n8n host. With a NAT / host-only VM network, use the host's address on that virtual network, allow TCP 5678 through the host firewall for that network only, and set `WEBHOOK_URL` accordingly. Details in [setup-wazuh.md](setup-wazuh.md).
