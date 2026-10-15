#!/usr/bin/env bash
# Replay a sample Wazuh alert against the n8n webhook.
# Usage: ./scripts/send-sample-alert.sh <alert.json> [webhook-url]
set -euo pipefail

FILE="${1:-}"
URL="${2:-http://localhost:5678/webhook/wazuh-alert}"

if [[ -z "$FILE" || ! -f "$FILE" ]]; then
  echo "Usage: $0 <alert.json> [webhook-url]" >&2
  exit 1
fi

echo "POST $FILE -> $URL"
curl -sS -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST "$URL" \
  -H "Content-Type: application/json" \
  --data-binary "@$FILE"
