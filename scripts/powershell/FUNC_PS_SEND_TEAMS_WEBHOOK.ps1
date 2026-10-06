<#
.SYNOPSIS
    Sends an Adaptive Card or text message to a Microsoft Teams channel via Webhook.

.DESCRIPTION
    Standardized notification tool.
    1. Formats JSON payload for Teams Webhooks.
    2. Submits POST request.
    SAFEGUARDS: Supports -TargetEnvironment.

.PARAMETER WebhookUrl
    The Teams incoming webhook URL.

.PARAMETER Title
    The card title.

.PARAMETER Message
    The message body.

.PARAMETER TargetEnvironment
    'Test' and 'Prod' both send messages for validation.

.EXAMPLE
    .\Send-TeamsWebhook.ps1 -WebhookUrl "https://outlook.office.com/webhook/..." -Title "Security Alert" -Message "Unauthorized login" -TargetEnvironment Prod

.NOTES
    Security Domain: Application
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-02-06T10:10:00
    KB Article: [KB-Rest-006-TeamsWebhooks.md](../../HowTo/Scripts/KB-Rest-006-TeamsWebhooks.md)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$WebhookUrl,

    [Parameter(Mandatory=$true)]
    [string]$Title,

    [Parameter(Mandatory=$true)]
    [string]$Message,

    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- MS Teams Notification Tool ---" -ForegroundColor Cyan

$Payload = @{
    "@type" = "MessageCard"
    "@context" = "https://schema.org/extensions"
    "themeColor" = "0076D7"
    "summary" = $Title
    "sections" = @(
        @{
            "activityTitle" = $Title
            "activitySubtitle" = "Environment: $TargetEnvironment"
            "text" = $Message
        }
    )
} | ConvertTo-Json

try {
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $Payload -ContentType 'application/json' -ErrorAction Stop
    Write-Host "[OK] Message sent to Teams." -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Error sending to Teams: $($_.Exception.Message)" -ForegroundColor Red
}
