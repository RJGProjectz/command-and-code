<#
.SYNOPSIS
    Sends a notification message to a Slack channel via Webhook.

.DESCRIPTION
    Standardized notification tool.
    1. Formats JSON payload for Slack.
    2. Submits POST request to the webhook URL.
    SAFEGUARDS: Supports -TargetEnvironment.

.PARAMETER WebhookUrl
    The Slack incoming webhook URL.

.PARAMETER Text
    The message content to send.

.PARAMETER TargetEnvironment
    'Test' and 'Prod' both send messages for validation.

.EXAMPLE
    .\Send-SlackWebhook.ps1 -WebhookUrl "https://hooks.slack.com/..." -Text "Alert: Ransomware detected on WS-1234" -TargetEnvironment Prod

.NOTES
    Security Domain: Application
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Rest-005-SlackWebhooks.md](../../HowTo/Scripts/KB-Rest-005-SlackWebhooks.md)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$WebhookUrl,

    [Parameter(Mandatory=$true)]
    [string]$Text,

    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Slack Notification Tool ---" -ForegroundColor Cyan

$Payload = @{ "text" = "[$TargetEnvironment] $Text" } | ConvertTo-Json

try {
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $Payload -ContentType 'application/json' -ErrorAction Stop
    Write-Host "[OK] Message sent to Slack." -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Error sending to Slack: $($_.Exception.Message)" -ForegroundColor Red
}
