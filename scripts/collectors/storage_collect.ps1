<#
Collect storage account configuration (supportsHttpsTrafficOnly, allowBlobPublicAccess) via Resource Graph or Az.Storage.
Writes evidence JSON and optionally posts to API.
#>
param(
    [string]$OutputPath = "./evidence_storage.json",
    [string]$ApiEndpoint = "http://localhost:8000/evidence"
)

if (-not (Get-Module -ListAvailable -Name Az.Storage)) {
    Write-Host "Az.Storage module not found. Run: Install-Module -Name Az.Storage -Scope CurrentUser" -ForegroundColor Yellow
}

try {
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        Write-Host "Not connected to Az account. Run Connect-AzAccount" -ForegroundColor Yellow
    }

    $query = "Resources | where type =~ 'microsoft.storage/storageaccounts' | project id, name, location, subscriptionId, properties.supportsHttpsTrafficOnly, properties.allowBlobPublicAccess"
    $results = Search-AzGraph -Query $query -First 1000

    $evidence = @{ Source = 'ARG'; QueryOrRequest = $query; Timestamp = (Get-Date).ToString('o'); RawResult = $results }
    $json = $evidence | ConvertTo-Json -Depth 6
    $json | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "Wrote evidence to $OutputPath"

    if ($PSBoundParameters.ContainsKey('ApiEndpoint') -and $ApiEndpoint) {
        Write-Host "Posting evidence to $ApiEndpoint"
        try {
            Invoke-RestMethod -Uri $ApiEndpoint -Method Post -ContentType 'application/json' -Body $json
            Write-Host "Posted evidence to API"
        }
        catch {
            Write-Warning "Failed to POST to API: $_"
        }
    }
}
catch {
    Write-Error "Error collecting storage evidence: $_"
}
