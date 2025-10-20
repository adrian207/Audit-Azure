<#
Run a simple pipeline: run a collector script (which writes a local evidence file), POST the evidence to the API, then trigger evaluation.
Usage:
pwsh ./scripts/run_pipeline.ps1 -CollectorPath .\scripts\collectors\nsg_collect.ps1 -ApiEndpoint http://localhost:8000 -Evaluator NET-001

Collector should support -OutputPath parameter. We pass -ApiEndpoint '' to prevent the collector from auto-posting.
#>
param(
    [Parameter(Mandatory = $true)] [string]$CollectorPath,
    [Parameter(Mandatory = $true)] [string]$Evaluator,
    [string]$ApiEndpoint = "http://localhost:8000",
    [string]$TmpDir = "./tmp"
)

if (-not (Test-Path $TmpDir)) { New-Item -ItemType Directory -Path $TmpDir | Out-Null }
$evidenceFile = Join-Path $TmpDir ([Guid]::NewGuid().ToString() + "_evidence.json")

Write-Host "Running collector: $CollectorPath -> $evidenceFile"

# Run collector in a separate PowerShell process to avoid parameter collision
$collectorArgs = @('-NoProfile', '-NoLogo', '-NonInteractive', '-File', $CollectorPath, '-OutputPath', $evidenceFile, '-ApiEndpoint', '')
Start-Process -FilePath pwsh -ArgumentList $collectorArgs -Wait -NoNewWindow -ErrorAction Stop

if (-not (Test-Path $evidenceFile)) {
    Write-Error "Collector did not produce evidence file: $evidenceFile"
    exit 2
}

$json = Get-Content $evidenceFile -Raw
Write-Host "Posting evidence to $ApiEndpoint/evidence"
try {
    $resp = Invoke-RestMethod -Uri "$ApiEndpoint/evidence" -Method Post -ContentType 'application/json' -Body $json
    $evidenceId = $resp.EvidenceId
    Write-Host "API returned EvidenceId: $evidenceId"
}
catch {
    Write-Error "Failed to POST evidence: $_"
    exit 3
}

# Trigger evaluation
$evalBody = @{ evidenceId = $evidenceId; evaluator = $Evaluator } | ConvertTo-Json -Depth 4
Write-Host "Triggering evaluation ($Evaluator)"
try {
    $evalResp = Invoke-RestMethod -Uri "$ApiEndpoint/evaluate" -Method Post -ContentType 'application/json' -Body $evalBody
    Write-Host "Evaluation response:`n" (ConvertTo-Json $evalResp -Depth 4)
}
catch {
    Write-Error "Evaluation failed: $_"
    exit 4
}

Write-Host "Pipeline completed. Findings created: $($evalResp.count)"
