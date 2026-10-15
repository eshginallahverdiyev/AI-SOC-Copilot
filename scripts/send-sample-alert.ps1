<#
  Replay a sample Wazuh alert against the n8n webhook (Windows PowerShell).
  Usage: .\scripts\send-sample-alert.ps1 -File samples\wazuh\new-user-created.json
         .\scripts\send-sample-alert.ps1 -File <alert.json> -Url http://localhost:5678/webhook/wazuh-alert
#>
param(
  [Parameter(Mandatory = $true)][string]$File,
  [string]$Url = "http://localhost:5678/webhook/wazuh-alert"
)

if (-not (Test-Path $File)) { Write-Error "File not found: $File"; exit 1 }

Write-Host "POST $File -> $Url"
$body = Get-Content -Raw -Path $File
$response = Invoke-WebRequest -Uri $Url -Method Post -ContentType "application/json" -Body $body -UseBasicParsing
Write-Host "HTTP $($response.StatusCode)"
