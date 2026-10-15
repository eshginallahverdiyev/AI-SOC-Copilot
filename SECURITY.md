# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **Security -> Report a vulnerability** feature on this repository rather than opening a public issue. Include steps to reproduce and the affected file or node.

## Handling secrets

- Never commit API keys, OAuth client secrets or real mailbox addresses. The exported workflows contain no credentials; the Gmail *send* nodes use the placeholder `YOUR_EMAIL@gmail.com`.
- Run `npm run scan` before every commit (CI runs it too).
- If a key was ever pasted into a screenshot, chat or commit, **rotate it** in the provider's console.

## Deployment hardening checklist

- [ ] The n8n webhook is reachable only from the Wazuh manager (firewall / IP allow-list), or sits behind a reverse proxy that requires authentication.
- [ ] n8n is not exposed to the internet; if remote access is required, use a VPN or an authenticated reverse proxy with TLS.
- [ ] `N8N_ENCRYPTION_KEY` is set once and backed up.
- [ ] A paid Gemini key (or other model with a no-training data policy) is used for real data.
- [ ] Google OAuth app is published, or the 7-day token expiry in *Testing* mode is acknowledged.
- [ ] Do not submit private/internal URLs or confidential e-mails to external scanners.
